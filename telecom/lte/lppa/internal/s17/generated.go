// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s17 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s17

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// AssistanceInformationFeedbackIEContainer is ProtocolIE-Container {{AssistanceInformationFeedback-IEs}} of TS 36.455: a list of AssistanceInformationFeedbackIEField values.
type AssistanceInformationFeedbackIEContainer []AssistanceInformationFeedbackIEField

// AssistanceInformationFeedbackIEField is ProtocolIE-Field {{AssistanceInformationFeedback-IEs}} of TS 36.455: a field carrying a value of AssistanceInformationFeedbackIEValue.
type AssistanceInformationFeedbackIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         AssistanceInformationFeedbackIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFeedbackIEField) WithoutReplay() AssistanceInformationFeedbackIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationFeedbackIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFeedbackIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *AssistanceInformationFeedbackIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFeedbackIEField{}
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
	var zero AssistanceInformationFeedbackIEValue

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
func BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEContainer(v *AssistanceInformationFeedbackIEContainer, s *aper.SemanticCapture) {
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
			BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEContainer(v *AssistanceInformationFeedbackIEContainer, s *aper.SemanticComparison) {
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
			BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEContainer(v *s11.UTDOAInformationUpdateIEContainer, s *aper.SemanticCapture) {
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
			BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEContainer(v *s11.UTDOAInformationUpdateIEContainer, s *aper.SemanticComparison) {
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
			BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding binds AssistanceInformationFailureList to ProtocolIE-Field {{AssistanceInformationFeedback-IEs}} of TS 36.455.
type AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding struct {
	info   s00.FieldInfo
	codec  s05.AssistanceInformationFailureListValueCodec
	inject func(s05.AssistanceInformationFailureList,

	) AssistanceInformationFeedbackIEValue

	get func(*AssistanceInformationFeedbackIEValue,

	) (*s05.AssistanceInformationFailureList,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Codec() s05.AssistanceInformationFailureListValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) New(value s05.AssistanceInformationFailureList,

) (AssistanceInformationFeedbackIEField, error) {
	if b.inject == nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeAssistanceInformationFailureListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Get(field *AssistanceInformationFeedbackIEField) (*s05.AssistanceInformationFailureList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to ProtocolIE-Field {{AssistanceInformationFeedback-IEs}} of TS 36.455.
type AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) AssistanceInformationFeedbackIEValue

	get func(*AssistanceInformationFeedbackIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (AssistanceInformationFeedbackIEField, error) {
	if b.inject == nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Get(field *AssistanceInformationFeedbackIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationFeedbackValueCodec is the concrete ValueCodec[AssistanceInformationFeedback].
type AssistanceInformationFeedbackValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformationFeedback, aper.DecodeState,

	) (AssistanceInformationFeedback, aper.Snapshot,

	)
	compare func(AssistanceInformationFeedback, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformationFeedback,

		error)
	encode func(AssistanceInformationFeedback,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationFeedbackValueCodec) New(value AssistanceInformationFeedback,

) (AssistanceInformationFeedbackAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFeedbackAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFeedbackAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationFeedbackValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationFeedbackAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFeedbackAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationFeedbackAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFeedbackAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFeedbackAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationFeedbackAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationFeedbackValueCodec) EncodeAPER(value AssistanceInformationFeedbackAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationFeedbackValueCodec) encodeBudget(value AssistanceInformationFeedback,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFeedbackValueCodec) encodeChanged(value AssistanceInformationFeedback,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTDOAInformationResponseValueCodec is the concrete ValueCodec[UTDOAInformationResponse].
type UTDOAInformationResponseValueCodec struct {
	context s00.BridgeCodecContext
	capture func(UTDOAInformationResponse, aper.DecodeState,

	) (UTDOAInformationResponse, aper.Snapshot,

	)
	compare func(UTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (UTDOAInformationResponse,

		error)
	encode func(UTDOAInformationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTDOAInformationResponseValueCodec) New(value UTDOAInformationResponse,

) (UTDOAInformationResponseAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTDOAInformationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTDOAInformationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTDOAInformationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTDOAInformationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTDOAInformationResponseValueCodec) EncodeAPER(value UTDOAInformationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTDOAInformationResponseValueCodec) encodeBudget(value UTDOAInformationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationResponseValueCodec) encodeChanged(value UTDOAInformationResponse,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTDOAInformationUpdateValueCodec is the concrete ValueCodec[UTDOAInformationUpdate].
type UTDOAInformationUpdateValueCodec struct {
	context s00.BridgeCodecContext
	capture func(UTDOAInformationUpdate, aper.DecodeState,

	) (UTDOAInformationUpdate, aper.Snapshot,

	)
	compare func(UTDOAInformationUpdate, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (UTDOAInformationUpdate,

		error)
	encode func(UTDOAInformationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTDOAInformationUpdateValueCodec) New(value UTDOAInformationUpdate,

) (UTDOAInformationUpdateAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationUpdateAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationUpdateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationUpdateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationUpdateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTDOAInformationUpdateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTDOAInformationUpdateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationUpdateAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTDOAInformationUpdateAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationUpdateAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationUpdateAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTDOAInformationUpdateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTDOAInformationUpdateValueCodec) EncodeAPER(value UTDOAInformationUpdateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTDOAInformationUpdateValueCodec) encodeBudget(value UTDOAInformationUpdate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationUpdateValueCodec) encodeChanged(value UTDOAInformationUpdate,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(fields s10.UTDOAInformationResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s10.BridgeUTDOAInformationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s10.BridgeUTDOAInformationResponseIEValueMethodRule(field.Value)
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
func BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(fields s11.UTDOAInformationUpdateIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s11.BridgeUTDOAInformationUpdateIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s11.BridgeUTDOAInformationUpdateIEValueMethodRule(field.Value)
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
func BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(fields AssistanceInformationFeedbackIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// assistanceInformationFeedbackIEValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) AssistanceInformationFeedbackIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (AssistanceInformationFeedbackIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEField(v *AssistanceInformationFeedbackIEField, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEField(v *AssistanceInformationFeedbackIEField, s *aper.SemanticComparison) {
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

// uTDOAInformationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.UTDOAInformationResponseIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.UTDOAInformationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uTDOAInformationUpdateIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s11.UTDOAInformationUpdateIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s11.UTDOAInformationUpdateIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEField(v *s11.UTDOAInformationUpdateIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s11.BridgeUTDOAInformationUpdateIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s11.BridgeUTDOAInformationUpdateIEValueMethodCaptureFraming(v.Value))
	v.Value = s11.BridgeUTDOAInformationUpdateIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s11.BridgeUTDOAInformationUpdateIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s11.BridgeUTDOAInformationUpdateIEFieldFieldReplay(v), *s11.BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEField(v *s11.UTDOAInformationUpdateIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s11.BridgeUTDOAInformationUpdateIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s11.BridgeUTDOAInformationUpdateIEFieldFieldReplay(v), *s11.BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v))
}

// AssistanceInformationFeedbackAPERValue is the concrete APERValue[AssistanceInformationFeedback].
type AssistanceInformationFeedbackAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformationFeedback

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationFeedbackAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFeedbackAPERValue) WithoutReplay() AssistanceInformationFeedbackAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationResponseAPERValue is the concrete APERValue[UTDOAInformationResponse].
type UTDOAInformationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UTDOAInformationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTDOAInformationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationResponseAPERValue) WithoutReplay() UTDOAInformationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationUpdateAPERValue is the concrete APERValue[UTDOAInformationUpdate].
type UTDOAInformationUpdateAPERValue struct {
	context s00.BridgeCodecContext
	Value   UTDOAInformationUpdate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTDOAInformationUpdateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationUpdateAPERValue) WithoutReplay() UTDOAInformationUpdateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellsComplete carries a complete AddOTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s15.AddOTDOACells
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *AddOTDOACellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERAddOTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AddOTDOACells from APER format.
func (v *AddOTDOACellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AddOTDOACellsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACells")
	}
	bb.EnterComponent("AddOTDOACells")
	value, err := BridgeUnmarshalAPERAddOTDOACellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACells")
	}
	padding, err := aper.CaptureFinalBits(bb, "AddOTDOACells")
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACells")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAddOTDOACells encodes a AddOTDOACells list to APER.
func BridgeMarshalAPERAddOTDOACells(list AddOTDOACellsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAddOTDOACells decodes a AddOTDOACells list from APER.
func BridgeUnmarshalAPERAddOTDOACells(data []byte) (AddOTDOACellsComplete, error) {
	var value AddOTDOACellsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellsFrom decodes a AddOTDOACells list from bb.
func BridgeUnmarshalAPERAddOTDOACellsFrom(bb *aper.BitBuffer) (s15.AddOTDOACells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s15.BridgeAsn1cAPERAddOTDOACellsListValue
	if err := BridgeUnmarshalAPERAddOTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAddOTDOACellsInto(v *s15.BridgeAsn1cAPERAddOTDOACellsListValue, bb *aper.BitBuffer) error {
	v.Value = make(s15.AddOTDOACells, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.AddOTDOACellsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeAddOTDOACellsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// AddOTDOACellInformationComplete carries a complete AddOTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellInformationComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s15.AddOTDOACellInformation
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *AddOTDOACellInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s16.BridgeMarshalAPERAddOTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AddOTDOACellInformation from APER format.
func (v *AddOTDOACellInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AddOTDOACellInformationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	bb.EnterComponent("AddOTDOACellInformation")
	value, err := BridgeUnmarshalAPERAddOTDOACellInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "AddOTDOACellInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAddOTDOACellInformation encodes a AddOTDOACellInformation list to APER.
func BridgeMarshalAPERAddOTDOACellInformation(list AddOTDOACellInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAddOTDOACellInformation decodes a AddOTDOACellInformation list from APER.
func BridgeUnmarshalAPERAddOTDOACellInformation(data []byte) (AddOTDOACellInformationComplete, error) {
	var value AddOTDOACellInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellInformationFrom decodes a AddOTDOACellInformation list from bb.
func BridgeUnmarshalAPERAddOTDOACellInformationFrom(bb *aper.BitBuffer) (s15.AddOTDOACellInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s15.BridgeAsn1cAPERAddOTDOACellInformationListValue
	if err := BridgeUnmarshalAPERAddOTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAddOTDOACellInformationInto(v *s15.BridgeAsn1cAPERAddOTDOACellInformationListValue, bb *aper.BitBuffer) error {
	v.Value = make(s15.AddOTDOACellInformation, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// AssistanceInformationFailureListComplete carries a complete AssistanceInformationFailureList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AssistanceInformationFailureListComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s05.AssistanceInformationFailureList
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *AssistanceInformationFailureListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERAssistanceInformationFailureListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AssistanceInformationFailureList from APER format.
func (v *AssistanceInformationFailureListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AssistanceInformationFailureListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	bb.EnterComponent("AssistanceInformationFailureList")
	value, err := BridgeUnmarshalAPERAssistanceInformationFailureListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformationFailureList")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAssistanceInformationFailureList encodes a AssistanceInformationFailureList list to APER.
func BridgeMarshalAPERAssistanceInformationFailureList(list AssistanceInformationFailureListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAssistanceInformationFailureList decodes a AssistanceInformationFailureList list from APER.
func BridgeUnmarshalAPERAssistanceInformationFailureList(data []byte) (AssistanceInformationFailureListComplete, error) {
	var value AssistanceInformationFailureListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAssistanceInformationFailureListFrom decodes a AssistanceInformationFailureList list from bb.
func BridgeUnmarshalAPERAssistanceInformationFailureListFrom(bb *aper.BitBuffer) (s05.AssistanceInformationFailureList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERAssistanceInformationFailureListListValue
	if err := BridgeUnmarshalAPERAssistanceInformationFailureListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAssistanceInformationFailureListInto(v *s09.BridgeAsn1cAPERAssistanceInformationFailureListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s05.AssistanceInformationFailureList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s05.AssistanceInformationFailureListElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s05.BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s05.CriticalityDiagnosticsIEList
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *CriticalityDiagnosticsIEListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CriticalityDiagnosticsIEList from APER format.
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	bb.EnterComponent("CriticalityDiagnosticsIEList")
	value, err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CriticalityDiagnosticsIEList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a CriticalityDiagnosticsIEList list to APER.
func BridgeMarshalAPERCriticalityDiagnosticsIEList(list CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a CriticalityDiagnosticsIEList list from APER.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEList(data []byte) (CriticalityDiagnosticsIEListComplete, error) {
	var value CriticalityDiagnosticsIEListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCriticalityDiagnosticsIEListFrom decodes a CriticalityDiagnosticsIEList list from bb.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb *aper.BitBuffer) (s05.CriticalityDiagnosticsIEList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue
	if err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(v *s09.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s05.CriticalityDiagnosticsIEList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s05.CriticalityDiagnosticsIEListElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s05.BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// InterRATMeasurementQuantitiesComplete carries a complete InterRATMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementQuantitiesComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s06.InterRATMeasurementQuantities
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *InterRATMeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERInterRATMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes InterRATMeasurementQuantities from APER format.
func (v *InterRATMeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *InterRATMeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	bb.EnterComponent("InterRATMeasurementQuantities")
	value, err := BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterRATMeasurementQuantities")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERInterRATMeasurementQuantities encodes a InterRATMeasurementQuantities list to APER.
func BridgeMarshalAPERInterRATMeasurementQuantities(list InterRATMeasurementQuantitiesComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERInterRATMeasurementQuantities decodes a InterRATMeasurementQuantities list from APER.
func BridgeUnmarshalAPERInterRATMeasurementQuantities(data []byte) (InterRATMeasurementQuantitiesComplete, error) {
	var value InterRATMeasurementQuantitiesComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementQuantitiesFrom decodes a InterRATMeasurementQuantities list from bb.
func BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(bb *aper.BitBuffer) (s06.InterRATMeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERInterRATMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERInterRATMeasurementQuantitiesInto(v *s09.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue, bb *aper.BitBuffer) error {
	v.Value = make(s06.InterRATMeasurementQuantities, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s06.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s06.BridgeInterRATMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// UnmarshalAPERMBSFNsubframeConfigurationFrom decodes a MBSFNsubframeConfiguration list from bb.
func BridgeUnmarshalAPERMBSFNsubframeConfigurationFrom(bb *aper.BitBuffer) (s09.MBSFNsubframeConfiguration, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue
	if err := BridgeUnmarshalAPERMBSFNsubframeConfigurationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMBSFNsubframeConfigurationInto(v *s09.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue, bb *aper.BitBuffer) error {
	v.Value = make(s09.MBSFNsubframeConfiguration, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s09.MBSFNsubframeConfigurationValue
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s09.BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
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
		return errCollection_value
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AddOTDOACellInformationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellInformationComplete) WithoutReplay() AddOTDOACellInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AddOTDOACellInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AddOTDOACellsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellsComplete) WithoutReplay() AddOTDOACellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AddOTDOACellsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationFailureListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFailureListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFailureListComplete) WithoutReplay() AssistanceInformationFailureListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformationFailureListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEListComplete) WithoutReplay() CriticalityDiagnosticsIEListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero CriticalityDiagnosticsIEListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasurementQuantitiesComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementQuantitiesComplete) WithoutReplay() InterRATMeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero InterRATMeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AddOTDOACellInformationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellInformationComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AddOTDOACellInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AddOTDOACellInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AddOTDOACellInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AddOTDOACellInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AddOTDOACellInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AddOTDOACellInformationComplete")
}
func (v *AddOTDOACellInformationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellInformationComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellInformationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAddOTDOACellInformationComplete(v, &s)
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
func (v *AddOTDOACellInformationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellInformationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s16.BridgeMarshalAPERAddOTDOACellInformationTo(value.Value, bb, fresh); err != nil {
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
func (v *AddOTDOACellsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AddOTDOACellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AddOTDOACellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AddOTDOACellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AddOTDOACellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AddOTDOACellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AddOTDOACellsComplete")
}
func (v *AddOTDOACellsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAddOTDOACellsComplete(v, &s)
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
func (v *AddOTDOACellsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s16.BridgeMarshalAPERAddOTDOACellsTo(value.Value, bb, fresh); err != nil {
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
func (v *AssistanceInformationFailureListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFailureListComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFailureListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformationFailureListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformationFailureListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformationFailureListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformationFailureListComplete")
}
func (v *AssistanceInformationFailureListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationFailureListComplete(v, &s)
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
func (v *AssistanceInformationFailureListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERAssistanceInformationFailureListTo(value.Value, bb, fresh); err != nil {
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
func (v *CriticalityDiagnosticsIEListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v, &s)
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
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(value.Value, bb, fresh); err != nil {
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
func (v *InterRATMeasurementQuantitiesComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v, &s)
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
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERInterRATMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
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
func (v *AddOTDOACellInformationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellInformationComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellInformationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellInformationComplete{}
		return report, aper.OperationError(err, "AddOTDOACellInformationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AddOTDOACellInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AddOTDOACellsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AddOTDOACellsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellsComplete{}
		return report, aper.OperationError(err, "AddOTDOACellsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AddOTDOACellsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AssistanceInformationFailureListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFailureListComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFailureListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFailureListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFailureListComplete{}
		return report, aper.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformationFailureListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *CriticalityDiagnosticsIEListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnosticsIEListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnosticsIEListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEListComplete{}
		return report, aper.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CriticalityDiagnosticsIEListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *InterRATMeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementQuantitiesComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementQuantitiesComplete{}
		return report, aper.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterRATMeasurementQuantitiesComplete")
}

// MarshalAPERAddOTDOACells encodes a complete named list.
func MarshalAPERAddOTDOACells(v AddOTDOACellsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERAddOTDOACellInformation encodes a complete named list.
func MarshalAPERAddOTDOACellInformation(v AddOTDOACellInformationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERAssistanceInformationFailureList encodes a complete named list.
func MarshalAPERAssistanceInformationFailureList(v AssistanceInformationFailureListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a complete named list.
func MarshalAPERCriticalityDiagnosticsIEList(v CriticalityDiagnosticsIEListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERInterRATMeasurementQuantities encodes a complete named list.
func MarshalAPERInterRATMeasurementQuantities(v InterRATMeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERAddOTDOACells decodes a complete named list.
func UnmarshalAPERAddOTDOACells(data []byte, options ...aper.DecodeOption) (AddOTDOACellsComplete, aper.DecodeReport, error) {
	var v AddOTDOACellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERAddOTDOACellInformation decodes a complete named list.
func UnmarshalAPERAddOTDOACellInformation(data []byte, options ...aper.DecodeOption) (AddOTDOACellInformationComplete, aper.DecodeReport, error) {
	var v AddOTDOACellInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERAssistanceInformationFailureList decodes a complete named list.
func UnmarshalAPERAssistanceInformationFailureList(data []byte, options ...aper.DecodeOption) (AssistanceInformationFailureListComplete, aper.DecodeReport, error) {
	var v AssistanceInformationFailureListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a complete named list.
func UnmarshalAPERCriticalityDiagnosticsIEList(data []byte, options ...aper.DecodeOption) (CriticalityDiagnosticsIEListComplete, aper.DecodeReport, error) {
	var v CriticalityDiagnosticsIEListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERInterRATMeasurementQuantities decodes a complete named list.
func UnmarshalAPERInterRATMeasurementQuantities(data []byte, options ...aper.DecodeOption) (InterRATMeasurementQuantitiesComplete, aper.DecodeReport, error) {
	var v InterRATMeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UTDOAInformationResponse represents the ASN.1 type UTDOAInformationResponse (SEQUENCE).
type UTDOAInformationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s10.UTDOAInformationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UTDOAInformationUpdate represents the ASN.1 type UTDOAInformationUpdate (SEQUENCE).
type UTDOAInformationUpdate struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s11.UTDOAInformationUpdateIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// AssistanceInformationFeedback represents the ASN.1 type AssistanceInformationFeedback (SEQUENCE).
type AssistanceInformationFeedback struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      AssistanceInformationFeedbackIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UTDOAInformationResponse to APER format.
func (v *UTDOAInformationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s10.BridgeUTDOAInformationResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UTDOAInformationResponse from APER format.
func (v *UTDOAInformationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UTDOAInformationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	bb.EnterComponent("UTDOAInformationResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UTDOAInformationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	v.perPadding = padding
	return nil
}
func (v *UTDOAInformationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s10.UTDOAInformationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.UTDOAInformationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s10.BridgeUTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UTDOAInformationUpdate to APER format.
func (v *UTDOAInformationUpdate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationUpdate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s11.BridgeUTDOAInformationUpdateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UTDOAInformationUpdate from APER format.
func (v *UTDOAInformationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UTDOAInformationUpdate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	bb.EnterComponent("UTDOAInformationUpdate")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	padding, err := aper.CaptureFinalBits(bb, "UTDOAInformationUpdate")
	if err != nil {
		return runtime.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	v.perPadding = padding
	return nil
}
func (v *UTDOAInformationUpdate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationUpdate{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s11.UTDOAInformationUpdateIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s11.UTDOAInformationUpdateIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s11.BridgeUTDOAInformationUpdateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes AssistanceInformationFeedback to APER format.
func (v *AssistanceInformationFeedback) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationFeedback) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes AssistanceInformationFeedback from APER format.
func (v *AssistanceInformationFeedback) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *AssistanceInformationFeedback) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	bb.EnterComponent("AssistanceInformationFeedback")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformationFeedback")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	v.perPadding = padding
	return nil
}
func (v *AssistanceInformationFeedback) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFeedback{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(AssistanceInformationFeedbackIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem AssistanceInformationFeedbackIEField
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
func (v *AssistanceInformationFeedback) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFeedback", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFeedback) WithoutReplay() AssistanceInformationFeedback {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformationFeedback
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationResponse) WithoutReplay() UTDOAInformationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero UTDOAInformationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationUpdate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationUpdate", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationUpdate) WithoutReplay() UTDOAInformationUpdate {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero UTDOAInformationUpdate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationFeedback) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationFeedback) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationFeedback) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationUpdate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationUpdate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationUpdate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AssistanceInformationFeedback) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFeedback")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFeedback(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformationFeedback")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformationFeedback")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformationFeedback")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformationFeedback")
}
func (v *AssistanceInformationFeedback) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFeedback) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFeedback) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationFeedback(v, &s)
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
func (v *AssistanceInformationFeedback) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFeedback) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *UTDOAInformationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "UTDOAInformationResponse")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "UTDOAInformationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "UTDOAInformationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "UTDOAInformationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "UTDOAInformationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "UTDOAInformationResponse")
}
func (v *UTDOAInformationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationResponse) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationResponse(v, &s)
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
func (v *UTDOAInformationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *UTDOAInformationUpdate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationUpdate")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationUpdate(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "UTDOAInformationUpdate")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "UTDOAInformationUpdate")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "UTDOAInformationUpdate")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "UTDOAInformationUpdate")
}
func (v *UTDOAInformationUpdate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationUpdate) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationUpdate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationUpdate(v, &s)
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
func (v *UTDOAInformationUpdate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationUpdate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformationFeedback) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformationFeedback")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFeedback
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFeedback(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFeedback{}
		return report, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformationFeedback")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationResponse")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationResponse{}
		return report, aper.OperationError(err, "UTDOAInformationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UTDOAInformationResponse")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationUpdate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UTDOAInformationUpdate")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationUpdate
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationUpdate(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationUpdate{}
		return report, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UTDOAInformationUpdate")
}
func BridgeCaptureLPPaAddOTDOACellInformationComplete(v *AddOTDOACellInformationComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s15.BridgeCaptureLPPaAddOTDOACellInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellInformationComplete(v *AddOTDOACellInformationComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s15.BridgeCompareLPPaAddOTDOACellInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAddOTDOACellsComplete(v *AddOTDOACellsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s15.BridgeCaptureLPPaAddOTDOACells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellsComplete(v *AddOTDOACellsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s15.BridgeCompareLPPaAddOTDOACells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFailureListComplete(v *AssistanceInformationFailureListComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s09.BridgeCaptureLPPaAssistanceInformationFailureList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFailureListComplete(v *AssistanceInformationFailureListComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s09.BridgeCompareLPPaAssistanceInformationFailureList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFeedback(v *AssistanceInformationFeedback, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFeedback(v *AssistanceInformationFeedback, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFeedbackIEValue(v *AssistanceInformationFeedbackIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformationFailureList == nil)
				if v.rowAssistanceInformationFailureList != nil {
					s09.BridgeCaptureLPPaAssistanceInformationFailureList(v.rowAssistanceInformationFailureList, s)
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
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationFeedbackIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AssistanceInformationFeedbackIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationFeedbackIEValue) captureSemantics(s aper.SemanticCapture) AssistanceInformationFeedbackIEValue {
	BridgeCaptureLPPaAssistanceInformationFeedbackIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationFeedbackIEValue(v *AssistanceInformationFeedbackIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformationFailureList == nil)
				if v.rowAssistanceInformationFailureList != nil {
					s09.BridgeCompareLPPaAssistanceInformationFailureList(v.rowAssistanceInformationFailureList, s)
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
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationFeedbackIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationFeedbackIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFeedbackIEValue) WithoutReplay() AssistanceInformationFeedbackIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s09.BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s09.BridgeCompareLPPaCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesComplete(v *InterRATMeasurementQuantitiesComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s11.BridgeCaptureLPPaInterRATMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v *InterRATMeasurementQuantitiesComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s11.BridgeCompareLPPaInterRATMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationResponse(v *UTDOAInformationResponse, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s16.BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationResponse(v *UTDOAInformationResponse, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s16.BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationUpdate(v *UTDOAInformationUpdate, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationUpdate(v *UTDOAInformationUpdate, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type AssistanceInformationFeedbackIEValue struct {
	id                                  s00.ProtocolIEID
	withoutReplay                       bool
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              *aper.OpaqueOpenType
	isOpaque                            bool
	rowAssistanceInformationFailureList *s05.AssistanceInformationFailureList
	rowCriticalityDiagnostics           *s09.CriticalityDiagnostics
}

func (v AssistanceInformationFeedbackIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(24):
		return v.rowAssistanceInformationFailureList != nil
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AssistanceInformationFeedbackIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationFeedbackIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs"}}
}
func (AssistanceInformationFeedbackIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(24):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
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
	case s00.ProtocolIEID(22):
		return aper.NotInTable
	case s00.ProtocolIEID(23):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsAssistanceInformationFailureList returns the selected AssistanceInformationFailureList value and reports whether that alternative is active.
func (v *AssistanceInformationFeedbackIEValue) AsAssistanceInformationFailureList() (*s05.AssistanceInformationFailureList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(24) || v.rowAssistanceInformationFailureList == nil {
		return nil, false
	}
	return v.rowAssistanceInformationFailureList, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *AssistanceInformationFeedbackIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v AssistanceInformationFeedbackIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceInformationFeedbackIEValue, error) {
	out := AssistanceInformationFeedbackIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 24, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(24):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERAssistanceInformationFailureListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AssistanceInformationFailureList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := AssistanceInformationFailureListComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAssistanceInformationFailureList = &value
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
func (v AssistanceInformationFeedbackIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationFeedbackIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(24):
		if v.rowAssistanceInformationFailureList == nil {
			return nil, fmt.Errorf("%s missing value", "AssistanceInformationFeedback-IEs.id-AssistanceInformationFailureList:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := AssistanceInformationFailureListComplete{Value: *v.rowAssistanceInformationFailureList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "AssistanceInformationFeedback-IEs.id-CriticalityDiagnostics:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceInformationFeedbackIEValue:", v.id)
	}
}

type AssistanceInformationFeedbackIETable struct{}

func AssistanceInformationFeedbackIEs() AssistanceInformationFeedbackIETable {
	return AssistanceInformationFeedbackIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (AssistanceInformationFeedbackIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs"}
		return sealed
	}()
}
func (AssistanceInformationFeedbackIETable) infoAssistanceInformationFailureList() s00.FieldInfo {
	return s00.FieldInfo{Table: AssistanceInformationFeedbackIEs().ID(), ID: s00.ProtocolIEID(24), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs", Row: "id-AssistanceInformationFailureList"}}}
}

// AssistanceInformationFailureList returns the selected sistanceInformationFailureList value and reports whether that alternative is active.
func (t AssistanceInformationFeedbackIETable) AssistanceInformationFailureList() AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding {
	return AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding{info: t.infoAssistanceInformationFailureList(), codec: func() s05.AssistanceInformationFailureListValueCodec {
		sealed := s05.AssistanceInformationFailureListValueCodec{}
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldPath(&sealed) = "AssistanceInformationFailureList"
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.AssistanceInformationFailureList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s05.AssistanceInformationFailureList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AssistanceInformationFailureList")
			var zero AssistanceInformationFeedbackIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(24), raw)
			if err != nil {
				var empty s05.AssistanceInformationFailureList
				return empty, runtime.WrapDecodePath(err, "AssistanceInformationFailureList")
			}
			value, ok := decoded.AsAssistanceInformationFailureList()
			if !ok {
				var empty s05.AssistanceInformationFailureList
				return empty, fmt.Errorf("binding AssistanceInformationFeedback-IEs.id-AssistanceInformationFailureList: no selected value")
			}
			return *value, nil
		}
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldEncode(&sealed) = func(value s05.AssistanceInformationFailureList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationFeedbackIEValue{id: s00.ProtocolIEID(24), rowAssistanceInformationFailureList: &value}).encodeFresh(fresh, budget)
		}
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldCapture(&sealed) = func(v s05.AssistanceInformationFailureList, options aper.DecodeState) (s05.AssistanceInformationFailureList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaAssistanceInformationFailureList(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)

			return v, root
		}
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldCompare(&sealed) = func(v s05.AssistanceInformationFailureList, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaAssistanceInformationFailureList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan()
		}
		*s05.BridgeAssistanceInformationFailureListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFailureList"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s05.AssistanceInformationFailureList) AssistanceInformationFeedbackIEValue {
			return AssistanceInformationFeedbackIEValue{id: s00.ProtocolIEID(24), rowAssistanceInformationFailureList: &value}
		}, get: func(value *AssistanceInformationFeedbackIEValue) (*s05.AssistanceInformationFailureList, bool) {
			return value.AsAssistanceInformationFailureList()
		}}
}
func (AssistanceInformationFeedbackIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: AssistanceInformationFeedbackIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t AssistanceInformationFeedbackIETable) CriticalityDiagnostics() AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding {
	return AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero AssistanceInformationFeedbackIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding AssistanceInformationFeedback-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationFeedbackIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s09.CriticalityDiagnostics) AssistanceInformationFeedbackIEValue {
			return AssistanceInformationFeedbackIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *AssistanceInformationFeedbackIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AssistanceInformationFeedbackIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AssistanceInformationFeedbackIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(24):
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("known IE id-AssistanceInformationFailureList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return AssistanceInformationFeedbackIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceInformationFeedbackIEField{Id: id, Criticality: criticality, Value: AssistanceInformationFeedbackIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AddOTDOACellInformationCodec binds the complete source value type.
func AddOTDOACellInformationCodec() s15.AddOTDOACellInformationValueCodec {
	return func() s15.AddOTDOACellInformationValueCodec {
		sealed := s15.AddOTDOACellInformationValueCodec{}
		*s15.BridgeAddOTDOACellInformationValueCodecFieldPath(&sealed) = "AddOTDOACellInformation"
		*s15.BridgeAddOTDOACellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.AddOTDOACellInformation, error) {
			var complete AddOTDOACellInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s15.AddOTDOACellInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*s15.BridgeAddOTDOACellInformationValueCodecFieldEncode(&sealed) = func(value s15.AddOTDOACellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := AddOTDOACellInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s15.BridgeAddOTDOACellInformationValueCodecFieldCapture(&sealed) = func(v s15.AddOTDOACellInformation, options aper.DecodeState) (s15.AddOTDOACellInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeCaptureLPPaAddOTDOACellInformation(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeAddOTDOACellInformationValueCodecFieldCompare(&sealed) = func(v s15.AddOTDOACellInformation, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s15.BridgeCompareLPPaAddOTDOACellInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s15.BridgeAddOTDOACellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACellInformation"
			return sealed
		}()
		return sealed
	}()

}

// AssistanceInformationFailureListCodec binds the complete APER value type.
func AssistanceInformationFailureListCodec() s05.AssistanceInformationFailureListValueCodec {
	return AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Codec()
}

// CriticalityDiagnosticsCodec binds the complete APER value type.
func CriticalityDiagnosticsCodec() s09.CriticalityDiagnosticsValueCodec {
	return AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Codec()
}

// CriticalityDiagnosticsIEListCodec binds the complete source value type.
func CriticalityDiagnosticsIEListCodec() s05.CriticalityDiagnosticsIEListValueCodec {
	return func() s05.CriticalityDiagnosticsIEListValueCodec {
		sealed := s05.CriticalityDiagnosticsIEListValueCodec{}
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsIEList"
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.CriticalityDiagnosticsIEList, error) {
			var complete CriticalityDiagnosticsIEListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s05.CriticalityDiagnosticsIEList
				return zero, err
			}
			return complete.Value, nil
		}
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(&sealed) = func(value s05.CriticalityDiagnosticsIEList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CriticalityDiagnosticsIEListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(&sealed) = func(v s05.CriticalityDiagnosticsIEList, options aper.DecodeState) (s05.CriticalityDiagnosticsIEList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(&sealed) = func(v s05.CriticalityDiagnosticsIEList, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnosticsIEList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s05.BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEList"
			return sealed
		}()
		return sealed
	}()

}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *AssistanceInformationFeedbackIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 24:
		if v.rowAssistanceInformationFailureList != nil {
			return v.rowAssistanceInformationFailureList, true
		}
	case 1:
		if v.rowCriticalityDiagnostics != nil {
			return v.rowCriticalityDiagnostics, true
		}
	}
	return nil, false
}

func BridgeAddOTDOACellInformationCompleteFieldPerPadding(v *AddOTDOACellInformationComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeAddOTDOACellInformationCompleteFieldReceived(v *AddOTDOACellInformationComplete) *bool {
	return &v.received
}
func BridgeAddOTDOACellInformationCompleteFieldReceivedBytes(v *AddOTDOACellInformationComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellInformationCompleteFieldReplay(v *AddOTDOACellInformationComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellInformationCompleteFieldStream(v *AddOTDOACellInformationComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellInformationCompleteFieldWithoutReplay(v *AddOTDOACellInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERBudget(v *AddOTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERChanged(v *AddOTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERChangedValue(v *AddOTDOACellInformationComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERFreshValue(v *AddOTDOACellInformationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERLegacy(v *AddOTDOACellInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERPlanned(v *AddOTDOACellInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodUnmarshalAPERLegacy(v *AddOTDOACellInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellInformationCompleteMethodUnmarshalAPERWithOptions(v *AddOTDOACellInformationComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAddOTDOACellsCompleteFieldPerPadding(v *AddOTDOACellsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeAddOTDOACellsCompleteFieldReceived(v *AddOTDOACellsComplete) *bool { return &v.received }
func BridgeAddOTDOACellsCompleteFieldReceivedBytes(v *AddOTDOACellsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellsCompleteFieldReplay(v *AddOTDOACellsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsCompleteFieldStream(v *AddOTDOACellsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellsCompleteFieldWithoutReplay(v *AddOTDOACellsComplete) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERBudget(v *AddOTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERChanged(v *AddOTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERChangedValue(v *AddOTDOACellsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERFreshValue(v *AddOTDOACellsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERLegacy(v *AddOTDOACellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERPlanned(v *AddOTDOACellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodUnmarshalAPERLegacy(v *AddOTDOACellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellsCompleteMethodUnmarshalAPERWithOptions(v *AddOTDOACellsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteFieldPerPadding(v *AssistanceInformationFailureListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFailureListCompleteFieldReceived(v *AssistanceInformationFailureListComplete) *bool {
	return &v.received
}
func BridgeAssistanceInformationFailureListCompleteFieldReceivedBytes(v *AssistanceInformationFailureListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFailureListCompleteFieldReplay(v *AssistanceInformationFailureListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListCompleteFieldStream(v *AssistanceInformationFailureListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListCompleteFieldWithoutReplay(v *AssistanceInformationFailureListComplete) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERBudget(v *AssistanceInformationFailureListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERChanged(v *AssistanceInformationFailureListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERChangedValue(v *AssistanceInformationFailureListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERFreshValue(v *AssistanceInformationFailureListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERLegacy(v *AssistanceInformationFailureListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERPlanned(v *AssistanceInformationFailureListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodUnmarshalAPERLegacy(v *AssistanceInformationFailureListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFailureListCompleteMethodUnmarshalAPERWithOptions(v *AssistanceInformationFailureListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFeedbackAPERValueFieldContext(v *AssistanceInformationFeedbackAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackAPERValueFieldReceived(v *AssistanceInformationFeedbackAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFeedbackAPERValueFieldReplay(v *AssistanceInformationFeedbackAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackAPERValueFieldWithoutReplay(v *AssistanceInformationFeedbackAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldCodec(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *s05.AssistanceInformationFailureListValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldGet(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *func(*AssistanceInformationFeedbackIEValue) (*s05.AssistanceInformationFailureList, bool) {
	return &v.get
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldInfo(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldInject(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *func(s05.AssistanceInformationFailureList) AssistanceInformationFeedbackIEValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldCodec(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldGet(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *func(*AssistanceInformationFeedbackIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldInfo(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldInject(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) AssistanceInformationFeedbackIEValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackFieldExtCount(v *AssistanceInformationFeedback) *int64 {
	return &v.extCount
}
func BridgeAssistanceInformationFeedbackFieldExtData(v *AssistanceInformationFeedback) *[][]byte {
	return &v.extData
}
func BridgeAssistanceInformationFeedbackFieldExtOrigin(v *AssistanceInformationFeedback) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFeedbackFieldExtPresent(v *AssistanceInformationFeedback) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFeedbackFieldExtWire(v *AssistanceInformationFeedback) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFeedbackFieldPerExtPadding(v *AssistanceInformationFeedback) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFeedbackFieldPerPadding(v *AssistanceInformationFeedback) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFeedbackFieldProtocolIEsIndef(v *AssistanceInformationFeedback) *bool {
	return &v.protocolIEsIndef
}
func BridgeAssistanceInformationFeedbackFieldReceived(v *AssistanceInformationFeedback) *bool {
	return &v.received
}
func BridgeAssistanceInformationFeedbackFieldReceivedBytes(v *AssistanceInformationFeedback) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFeedbackFieldReplay(v *AssistanceInformationFeedback) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackFieldStream(v *AssistanceInformationFeedback) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFeedbackFieldWithoutReplay(v *AssistanceInformationFeedback) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEFieldFieldReceived(v *AssistanceInformationFeedbackIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFeedbackIEFieldFieldReplay(v *AssistanceInformationFeedbackIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackIEFieldFieldStream(v *AssistanceInformationFeedbackIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFeedbackIEFieldFieldWithoutReplay(v *AssistanceInformationFeedbackIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEFieldMethodMarshalAPERTo(v *AssistanceInformationFeedbackIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFeedbackIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFeedbackIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFeedbackIETableMethodInfoAssistanceInformationFailureList(v AssistanceInformationFeedbackIETable) s00.FieldInfo {
	return v.infoAssistanceInformationFailureList()
}
func BridgeAssistanceInformationFeedbackIETableMethodInfoCriticalityDiagnostics(v AssistanceInformationFeedbackIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeAssistanceInformationFeedbackIEValueFieldId(v *AssistanceInformationFeedbackIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationFeedbackIEValueFieldIsOpaque(v *AssistanceInformationFeedbackIEValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationFeedbackIEValueFieldOpaque(v *AssistanceInformationFeedbackIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationFeedbackIEValueFieldReceived(v *AssistanceInformationFeedbackIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFeedbackIEValueFieldReplay(v *AssistanceInformationFeedbackIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackIEValueFieldRowAssistanceInformationFailureList(v *AssistanceInformationFeedbackIEValue) **s05.AssistanceInformationFailureList {
	return &v.rowAssistanceInformationFailureList
}
func BridgeAssistanceInformationFeedbackIEValueFieldRowCriticalityDiagnostics(v *AssistanceInformationFeedbackIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeAssistanceInformationFeedbackIEValueFieldWithoutReplay(v *AssistanceInformationFeedbackIEValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureFraming(v AssistanceInformationFeedbackIEValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureSemantics(v AssistanceInformationFeedbackIEValue, a0 aper.SemanticCapture) AssistanceInformationFeedbackIEValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureSnapshot(v AssistanceInformationFeedbackIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationFeedbackIEValueMethodCompareSemantics(v AssistanceInformationFeedbackIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodDecode(v AssistanceInformationFeedbackIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceInformationFeedbackIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodEncode(v AssistanceInformationFeedbackIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationFeedbackIEValueMethodEncodeFresh(v AssistanceInformationFeedbackIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodMatchesID(v AssistanceInformationFeedbackIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodReason(v AssistanceInformationFeedbackIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodRule(v AssistanceInformationFeedbackIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v *AssistanceInformationFeedback, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERChanged(v *AssistanceInformationFeedback, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERChangedValue(v *AssistanceInformationFeedback, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERFreshValue(v *AssistanceInformationFeedback, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERLegacy(v *AssistanceInformationFeedback) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERPlanned(v *AssistanceInformationFeedback, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERTo(v *AssistanceInformationFeedback, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERFrom(v *AssistanceInformationFeedback, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERLegacy(v *AssistanceInformationFeedback, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERWithOptions(v *AssistanceInformationFeedback, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFeedbackValueCodecFieldCapture(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, aper.DecodeState) (AssistanceInformationFeedback, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFeedbackValueCodecFieldCompare(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFeedbackValueCodecFieldContext(v *AssistanceInformationFeedbackValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackValueCodecFieldDecode(v *AssistanceInformationFeedbackValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformationFeedback, error) {
	return &v.decode
}
func BridgeAssistanceInformationFeedbackValueCodecFieldEncode(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFeedbackValueCodecFieldPath(v *AssistanceInformationFeedbackValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationFeedbackValueCodecMethodEncodeBudget(v AssistanceInformationFeedbackValueCodec, a0 AssistanceInformationFeedback, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackValueCodecMethodEncodeChanged(v AssistanceInformationFeedbackValueCodec, a0 AssistanceInformationFeedback, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldPerPadding(v *CriticalityDiagnosticsIEListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReceived(v *CriticalityDiagnosticsIEListComplete) *bool {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReceivedBytes(v *CriticalityDiagnosticsIEListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReplay(v *CriticalityDiagnosticsIEListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldStream(v *CriticalityDiagnosticsIEListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldWithoutReplay(v *CriticalityDiagnosticsIEListComplete) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERBudget(v *CriticalityDiagnosticsIEListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERChanged(v *CriticalityDiagnosticsIEListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERChangedValue(v *CriticalityDiagnosticsIEListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERFreshValue(v *CriticalityDiagnosticsIEListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERLegacy(v *CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERPlanned(v *CriticalityDiagnosticsIEListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodUnmarshalAPERLegacy(v *CriticalityDiagnosticsIEListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodUnmarshalAPERWithOptions(v *CriticalityDiagnosticsIEListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldPerPadding(v *InterRATMeasurementQuantitiesComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReceived(v *InterRATMeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReceivedBytes(v *InterRATMeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReplay(v *InterRATMeasurementQuantitiesComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldStream(v *InterRATMeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldWithoutReplay(v *InterRATMeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *InterRATMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *InterRATMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *InterRATMeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *InterRATMeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *InterRATMeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *InterRATMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *InterRATMeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *InterRATMeasurementQuantitiesComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationResponseAPERValueFieldContext(v *UTDOAInformationResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseAPERValueFieldReceived(v *UTDOAInformationResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationResponseAPERValueFieldReplay(v *UTDOAInformationResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseAPERValueFieldWithoutReplay(v *UTDOAInformationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseFieldExtCount(v *UTDOAInformationResponse) *int64 {
	return &v.extCount
}
func BridgeUTDOAInformationResponseFieldExtData(v *UTDOAInformationResponse) *[][]byte {
	return &v.extData
}
func BridgeUTDOAInformationResponseFieldExtOrigin(v *UTDOAInformationResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationResponseFieldExtPresent(v *UTDOAInformationResponse) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationResponseFieldExtWire(v *UTDOAInformationResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationResponseFieldPerExtPadding(v *UTDOAInformationResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationResponseFieldPerPadding(v *UTDOAInformationResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationResponseFieldProtocolIEsIndef(v *UTDOAInformationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationResponseFieldReceived(v *UTDOAInformationResponse) *bool {
	return &v.received
}
func BridgeUTDOAInformationResponseFieldReceivedBytes(v *UTDOAInformationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationResponseFieldReplay(v *UTDOAInformationResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseFieldStream(v *UTDOAInformationResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationResponseFieldWithoutReplay(v *UTDOAInformationResponse) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v *UTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERChanged(v *UTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERChangedValue(v *UTDOAInformationResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERFreshValue(v *UTDOAInformationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERLegacy(v *UTDOAInformationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationResponseMethodMarshalAPERPlanned(v *UTDOAInformationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERTo(v *UTDOAInformationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERFrom(v *UTDOAInformationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERLegacy(v *UTDOAInformationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERWithOptions(v *UTDOAInformationResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationResponseValueCodecFieldCapture(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, aper.DecodeState) (UTDOAInformationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationResponseValueCodecFieldCompare(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationResponseValueCodecFieldContext(v *UTDOAInformationResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseValueCodecFieldDecode(v *UTDOAInformationResponseValueCodec) *func([]byte, aper.DecodeState) (UTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeUTDOAInformationResponseValueCodecFieldEncode(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationResponseValueCodecFieldPath(v *UTDOAInformationResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUTDOAInformationResponseValueCodecMethodEncodeBudget(v UTDOAInformationResponseValueCodec, a0 UTDOAInformationResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationResponseValueCodecMethodEncodeChanged(v UTDOAInformationResponseValueCodec, a0 UTDOAInformationResponse, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationUpdateAPERValueFieldContext(v *UTDOAInformationUpdateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateAPERValueFieldReceived(v *UTDOAInformationUpdateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationUpdateAPERValueFieldReplay(v *UTDOAInformationUpdateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateAPERValueFieldWithoutReplay(v *UTDOAInformationUpdateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateFieldExtCount(v *UTDOAInformationUpdate) *int64   { return &v.extCount }
func BridgeUTDOAInformationUpdateFieldExtData(v *UTDOAInformationUpdate) *[][]byte { return &v.extData }
func BridgeUTDOAInformationUpdateFieldExtOrigin(v *UTDOAInformationUpdate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationUpdateFieldExtPresent(v *UTDOAInformationUpdate) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationUpdateFieldExtWire(v *UTDOAInformationUpdate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationUpdateFieldPerExtPadding(v *UTDOAInformationUpdate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationUpdateFieldPerPadding(v *UTDOAInformationUpdate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationUpdateFieldProtocolIEsIndef(v *UTDOAInformationUpdate) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationUpdateFieldReceived(v *UTDOAInformationUpdate) *bool { return &v.received }
func BridgeUTDOAInformationUpdateFieldReceivedBytes(v *UTDOAInformationUpdate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationUpdateFieldReplay(v *UTDOAInformationUpdate) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateFieldStream(v *UTDOAInformationUpdate) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationUpdateFieldWithoutReplay(v *UTDOAInformationUpdate) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v *UTDOAInformationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERChanged(v *UTDOAInformationUpdate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERChangedValue(v *UTDOAInformationUpdate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERFreshValue(v *UTDOAInformationUpdate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERLegacy(v *UTDOAInformationUpdate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERPlanned(v *UTDOAInformationUpdate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERTo(v *UTDOAInformationUpdate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERFrom(v *UTDOAInformationUpdate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERLegacy(v *UTDOAInformationUpdate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERWithOptions(v *UTDOAInformationUpdate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationUpdateValueCodecFieldCapture(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, aper.DecodeState) (UTDOAInformationUpdate, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationUpdateValueCodecFieldCompare(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationUpdateValueCodecFieldContext(v *UTDOAInformationUpdateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateValueCodecFieldDecode(v *UTDOAInformationUpdateValueCodec) *func([]byte, aper.DecodeState) (UTDOAInformationUpdate, error) {
	return &v.decode
}
func BridgeUTDOAInformationUpdateValueCodecFieldEncode(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationUpdateValueCodecFieldPath(v *UTDOAInformationUpdateValueCodec) *aper.Path {
	return &v.path
}
func BridgeUTDOAInformationUpdateValueCodecMethodEncodeBudget(v UTDOAInformationUpdateValueCodec, a0 UTDOAInformationUpdate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateValueCodecMethodEncodeChanged(v UTDOAInformationUpdateValueCodec, a0 UTDOAInformationUpdate, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
