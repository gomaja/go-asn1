// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s58 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s58

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewPrivateMessage(fields s29.PrivateMessageIEsValuePrivateIEContainer, options ...aper.BuildOption) (s30.PrivateMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s29.PrivateMessageIEsValuePrivateIEField](bb, uint64(len(fields))); err != nil {
		return s30.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	v := s30.PrivateMessage{PrivateIEs: append(s29.PrivateMessageIEsValuePrivateIEContainer(nil), fields...)}
	report, err := BridgeValidatePrivateMessageBudget(&v, budget)
	if err != nil {
		return s30.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.PrivateMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PrivateMessage")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.PrivateMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PrivateMessage")
	}
	if _, err := s30.BridgePrivateMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.PrivateMessage{}, aper.OperationError(fmt.Errorf("%s %w", "PrivateMessage.privateIEs:", err), "PrivateMessage")
	}
	return v, aper.OperationError(nil, "PrivateMessage")
}

// PathSwitchRequestAcknowledgeIEContainer is ProtocolIE-Container {{PathSwitchRequestAcknowledgeIEs}} of TS 36.413: a list of PathSwitchRequestAcknowledgeIEField values.
type PathSwitchRequestAcknowledgeIEContainer []PathSwitchRequestAcknowledgeIEField

// PathSwitchRequestAcknowledgeIEField is ProtocolIE-Field {{PathSwitchRequestAcknowledgeIEs}} of TS 36.413: an information element field.
type PathSwitchRequestAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PathSwitchRequestAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEField) WithoutReplay() PathSwitchRequestAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PathSwitchRequestAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PathSwitchRequestAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *PathSwitchRequestAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestAcknowledgeIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero PathSwitchRequestAcknowledgeIEValue

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

// UEContextModificationRequestIEContainer is ProtocolIE-Container {{UEContextModificationRequestIEs}} of TS 36.413: a list of UEContextModificationRequestIEField values.
type UEContextModificationRequestIEContainer []UEContextModificationRequestIEField

// UEContextModificationRequestIEField is ProtocolIE-Field {{UEContextModificationRequestIEs}} of TS 36.413: an information element field.
type UEContextModificationRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextModificationRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEField) WithoutReplay() UEContextModificationRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextModificationRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextModificationRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *UEContextModificationRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationRequestIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero UEContextModificationRequestIEValue

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
func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *PathSwitchRequestAcknowledgeIEContainer, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(v *PathSwitchRequestAcknowledgeIEContainer, s *aper.SemanticComparison) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(v *UEContextModificationRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(v *UEContextModificationRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.WLANMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.WLANMeasurementConfigurationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// V2XServicesAuthorizedValueCodec is the concrete ValueCodec[V2XServicesAuthorized].
type V2XServicesAuthorizedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s57.V2XServicesAuthorized,

		error)
	encode func(s57.V2XServicesAuthorized,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s57.V2XServicesAuthorized, aper.DecodeState,

	) (s57.V2XServicesAuthorized, aper.Snapshot,

	)
	compare func(s57.V2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c V2XServicesAuthorizedValueCodec) New(value s57.V2XServicesAuthorized,

) (V2XServicesAuthorizedAPERValue, error) {
	if c.encode == nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return V2XServicesAuthorizedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return V2XServicesAuthorizedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c V2XServicesAuthorizedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (V2XServicesAuthorizedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return V2XServicesAuthorizedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return V2XServicesAuthorizedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return V2XServicesAuthorizedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return V2XServicesAuthorizedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c V2XServicesAuthorizedValueCodec) EncodeAPER(value V2XServicesAuthorizedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c V2XServicesAuthorizedValueCodec) encodeBudgetValue(value s57.V2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c V2XServicesAuthorizedValueCodec) encodeChanged(value s57.V2XServicesAuthorized,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding binds MMEUES1APID to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeENBUES1APIDIEBinding binds ENBUES1APID to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeENBUES1APIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding binds UEAggregateMaximumBitrate to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s45.UEAggregateMaximumBitrateValueCodec
	inject func(s45.UEAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s45.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Codec() s45.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) New(value s45.UEAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s45.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding binds ERABToBeSwitchedULList to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ERABToBeSwitchedULListValueCodec
	inject func(s20.ERABToBeSwitchedULList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s20.ERABToBeSwitchedULList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Codec() s20.ERABToBeSwitchedULListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) New(value s20.ERABToBeSwitchedULList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeERABToBeSwitchedULListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s20.ERABToBeSwitchedULList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABListIEBinding binds ERABList to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeERABListIEBinding struct {
	info   s00.FieldInfo
	codec  s19.ERABListValueCodec
	inject func(s19.ERABList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s19.ERABList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Codec() s19.ERABListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) New(value s19.ERABList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeERABListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s19.ERABList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeSecurityContextIEBinding binds SecurityContext to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeSecurityContextIEBinding struct {
	info   s00.FieldInfo
	codec  s36.SecurityContextValueCodec
	inject func(s36.SecurityContext,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s36.SecurityContext,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Codec() s36.SecurityContextValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) New(value s36.SecurityContext,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeSecurityContextValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeSecurityContextIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s36.SecurityContext,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s26.CriticalityDiagnosticsValueCodec
	inject func(s26.CriticalityDiagnostics,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s26.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Codec() s26.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) New(value s26.CriticalityDiagnostics,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s26.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding binds CSGMembershipStatus to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding binds ProSeAuthorized to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s23.ProSeAuthorizedValueCodec
	inject func(s23.ProSeAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s23.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Codec() s23.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) New(value s23.ProSeAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s23.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding binds UEUserPlaneCIoTSupportIndicator to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUserPlaneCIoTSupportIndicatorValueCodec
	inject func(s00.UEUserPlaneCIoTSupportIndicator,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.UEUserPlaneCIoTSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Codec() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) New(value s00.UEUserPlaneCIoTSupportIndicator,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.UEUserPlaneCIoTSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding binds V2XServicesAuthorized to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  V2XServicesAuthorizedValueCodec
	inject func(s57.V2XServicesAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s57.V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Codec() V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) New(value s57.V2XServicesAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s57.V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding binds UESidelinkAggregateMaximumBitrate to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s47.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s47.UESidelinkAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s47.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Codec() s47.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) New(value s47.UESidelinkAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s47.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding binds EnhancedCoverageRestricted to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding binds NRUESecurityCapabilities to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRUESecurityCapabilitiesValueCodec
	inject func(s23.NRUESecurityCapabilities,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s23.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Codec() s23.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) New(value s23.NRUESecurityCapabilities,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s23.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding binds CEModeBRestricted to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding binds AerialUEsubscriptionInformation to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgePendingDataIndicationIEBinding binds PendingDataIndication to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgePendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgePendingDataIndicationIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding binds SubscriptionBasedUEDifferentiationInfo to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s39.SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s39.SubscriptionBasedUEDifferentiationInfo,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s39.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() s39.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s39.SubscriptionBasedUEDifferentiationInfo,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s39.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding binds HandoverRestrictionList to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding struct {
	info   s00.FieldInfo
	codec  s53.HandoverRestrictionListValueCodec
	inject func(s53.HandoverRestrictionList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s53.HandoverRestrictionList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Codec() s53.HandoverRestrictionListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) New(value s53.HandoverRestrictionList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s53.BridgeHandoverRestrictionListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s53.HandoverRestrictionList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding binds AdditionalRRMPriorityIndex to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding binds NRV2XServicesAuthorized to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRV2XServicesAuthorizedValueCodec
	inject func(s23.NRV2XServicesAuthorized,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s23.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Codec() s23.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) New(value s23.NRV2XServicesAuthorized,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s23.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding binds NRUESidelinkAggregateMaximumBitrate to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s23.NRUESidelinkAggregateMaximumBitrate,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s23.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s23.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s23.NRUESidelinkAggregateMaximumBitrate,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s23.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgePC5QoSParametersIEBinding binds PC5QoSParameters to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgePC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s28.PC5QoSParametersValueCodec
	inject func(s28.PC5QoSParameters,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s28.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Codec() s28.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) New(value s28.PC5QoSParameters,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgePC5QoSParametersIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s28.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding binds UERadioCapabilityID to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding binds UESecurityCapabilities to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s47.UESecurityCapabilitiesValueCodec
	inject func(s47.UESecurityCapabilities,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s47.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Codec() s47.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) New(value s47.UESecurityCapabilities,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s47.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s47.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding binds ERABToBeUpdatedList to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding struct {
	info   s00.FieldInfo
	codec  s37.ERABToBeUpdatedListValueCodec
	inject func(s37.ERABToBeUpdatedList,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s37.ERABToBeUpdatedList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Codec() s37.ERABToBeUpdatedListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) New(value s37.ERABToBeUpdatedList,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeERABToBeUpdatedListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s37.ERABToBeUpdatedList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding binds TimeRefDistribution to the PathSwitchRequestAcknowledgeIEs object set of TS 36.413.
type PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) PathSwitchRequestAcknowledgeIEValue

	get func(*PathSwitchRequestAcknowledgeIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (PathSwitchRequestAcknowledgeIEField, error) {
	if b.inject == nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding) Get(field *PathSwitchRequestAcknowledgeIEField) (*s00.TimeRefDistribution,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestMMEUES1APIDIEBinding binds MMEUES1APID to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestMMEUES1APIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestENBUES1APIDIEBinding binds ENBUES1APID to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestENBUES1APIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSecurityKeyIEBinding binds SecurityKey to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestSecurityKeyIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SecurityKeyValueCodec
	inject func(s00.SecurityKey,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SecurityKey,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Codec() s02.SecurityKeyValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSecurityKeyIEBinding) New(value s00.SecurityKey,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSecurityKeyValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSecurityKeyIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SecurityKey,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSubscriberProfileIDforRFPIEBinding binds SubscriberProfileIDforRFP to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestSubscriberProfileIDforRFPIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SubscriberProfileIDforRFPValueCodec
	inject func(s00.SubscriberProfileIDforRFP,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SubscriberProfileIDforRFP,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Codec() s02.SubscriberProfileIDforRFPValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) New(value s00.SubscriberProfileIDforRFP,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSubscriberProfileIDforRFPIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SubscriberProfileIDforRFP,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUEAggregateMaximumBitrateIEBinding binds UEAggregateMaximumBitrate to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s45.UEAggregateMaximumBitrateValueCodec
	inject func(s45.UEAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s45.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Codec() s45.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) New(value s45.UEAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUEAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s45.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestCSFallbackIndicatorIEBinding binds CSFallbackIndicator to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSFallbackIndicatorValueCodec
	inject func(s00.CSFallbackIndicator,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.CSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Codec() s00.CSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) New(value s00.CSFallbackIndicator,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestCSFallbackIndicatorIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.CSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUESecurityCapabilitiesIEBinding binds UESecurityCapabilities to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s47.UESecurityCapabilitiesValueCodec
	inject func(s47.UESecurityCapabilities,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s47.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Codec() s47.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) New(value s47.UESecurityCapabilities,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s47.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUESecurityCapabilitiesIEBinding) Get(field *UEContextModificationRequestIEField) (*s47.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestCSGMembershipStatusIEBinding binds CSGMembershipStatus to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestCSGMembershipStatusIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestLAIIEBinding binds LAI to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestLAIIEBinding struct {
	info   s00.FieldInfo
	codec  s22.LAIValueCodec
	inject func(s22.LAI,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s22.LAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestLAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestLAIIEBinding) Codec() s22.LAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestLAIIEBinding) New(value s22.LAI,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeLAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestLAIIEBinding) Get(field *UEContextModificationRequestIEField) (*s22.LAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding binds AdditionalCSFallbackIndicator to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalCSFallbackIndicatorValueCodec
	inject func(s00.AdditionalCSFallbackIndicator,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AdditionalCSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Codec() s00.AdditionalCSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) New(value s00.AdditionalCSFallbackIndicator,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AdditionalCSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestProSeAuthorizedIEBinding binds ProSeAuthorized to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s23.ProSeAuthorizedValueCodec
	inject func(s23.ProSeAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s23.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Codec() s23.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) New(value s23.ProSeAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestProSeAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s23.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSRVCCOperationPossibleIEBinding binds SRVCCOperationPossible to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestSRVCCOperationPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SRVCCOperationPossibleValueCodec
	inject func(s00.SRVCCOperationPossible,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SRVCCOperationPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Codec() s02.SRVCCOperationPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) New(value s00.SRVCCOperationPossible,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSRVCCOperationPossibleIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SRVCCOperationPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestSRVCCOperationNotPossibleIEBinding binds SRVCCOperationNotPossible to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestSRVCCOperationNotPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s02.SRVCCOperationNotPossibleValueCodec
	inject func(s00.SRVCCOperationNotPossible,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.SRVCCOperationNotPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Codec() s02.SRVCCOperationNotPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) New(value s00.SRVCCOperationNotPossible,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestSRVCCOperationNotPossibleIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.SRVCCOperationNotPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestV2XServicesAuthorizedIEBinding binds V2XServicesAuthorized to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  V2XServicesAuthorizedValueCodec
	inject func(s57.V2XServicesAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s57.V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Codec() V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) New(value s57.V2XServicesAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestV2XServicesAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s57.V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding binds UESidelinkAggregateMaximumBitrate to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s47.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s47.UESidelinkAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s47.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Codec() s47.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) New(value s47.UESidelinkAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s47.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRUESecurityCapabilitiesIEBinding binds NRUESecurityCapabilities to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRUESecurityCapabilitiesValueCodec
	inject func(s23.NRUESecurityCapabilities,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s23.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Codec() s23.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) New(value s23.NRUESecurityCapabilities,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRUESecurityCapabilitiesIEBinding) Get(field *UEContextModificationRequestIEField) (*s23.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAerialUEsubscriptionInformationIEBinding binds AerialUEsubscriptionInformation to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAerialUEsubscriptionInformationIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding binds AdditionalRRMPriorityIndex to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestIABAuthorizedIEBinding binds IABAuthorized to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestIABAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s01.IABAuthorizedValueCodec
	inject func(s00.IABAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.IABAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Codec() s01.IABAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestIABAuthorizedIEBinding) New(value s00.IABAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIABAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestIABAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.IABAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRV2XServicesAuthorizedIEBinding binds NRV2XServicesAuthorized to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRV2XServicesAuthorizedValueCodec
	inject func(s23.NRV2XServicesAuthorized,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s23.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Codec() s23.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) New(value s23.NRV2XServicesAuthorized,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRV2XServicesAuthorizedIEBinding) Get(field *UEContextModificationRequestIEField) (*s23.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding binds NRUESidelinkAggregateMaximumBitrate to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s23.NRUESidelinkAggregateMaximumBitrate,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s23.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s23.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s23.NRUESidelinkAggregateMaximumBitrate,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *UEContextModificationRequestIEField) (*s23.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestPC5QoSParametersIEBinding binds PC5QoSParameters to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestPC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s28.PC5QoSParametersValueCodec
	inject func(s28.PC5QoSParameters,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s28.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Codec() s28.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) New(value s28.PC5QoSParameters,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestPC5QoSParametersIEBinding) Get(field *UEContextModificationRequestIEField) (*s28.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestUERadioCapabilityIDIEBinding binds UERadioCapabilityID to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestUERadioCapabilityIDIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationRequestTimeRefDistributionIEBinding binds TimeRefDistribution to the UEContextModificationRequestIEs object set of TS 36.413.
type UEContextModificationRequestTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) UEContextModificationRequestIEValue

	get func(*UEContextModificationRequestIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (UEContextModificationRequestIEField, error) {
	if b.inject == nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextModificationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextModificationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextModificationRequestTimeRefDistributionIEBinding) Get(field *UEContextModificationRequestIEField) (*s00.TimeRefDistribution,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PathSwitchRequestAcknowledgeValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledge].
type PathSwitchRequestAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledge,

		error)
	encode func(PathSwitchRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledge, aper.DecodeState,

	) (PathSwitchRequestAcknowledge, aper.Snapshot,

	)
	compare func(PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeValueCodec) New(value PathSwitchRequestAcknowledge,

) (PathSwitchRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeValueCodec) encodeChanged(value PathSwitchRequestAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestValueCodec is the concrete ValueCodec[UEContextModificationRequest].
type UEContextModificationRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequest,

		error)
	encode func(UEContextModificationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequest, aper.DecodeState,

	) (UEContextModificationRequest, aper.Snapshot,

	)
	compare func(UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestValueCodec) New(value UEContextModificationRequest,

) (UEContextModificationRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestValueCodec) EncodeAPER(value UEContextModificationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestValueCodec) encodeBudgetValue(value UEContextModificationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestValueCodec) encodeChanged(value UEContextModificationRequest,

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
func BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(fields PathSwitchRequestAcknowledgeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(fields UEContextModificationRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields s14.V2XServicesAuthorizedExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.V2XServicesAuthorizedExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.V2XServicesAuthorizedExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeV2XServicesAuthorizedExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueERABIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec{path: "PathSwitchRequestAcknowledgeIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PathSwitchRequestAcknowledgeIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PathSwitchRequestAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledgeIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v PathSwitchRequestAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEContextModificationRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueERABIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) UEContextModificationRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextModificationRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextModificationRequestIEValueERABIEContainerListValueCodec{path: "UEContextModificationRequestIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextModificationRequestIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextModificationRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextModificationRequestIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextModificationRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextModificationRequestIEValueERABIEContainerList, options aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v UEContextModificationRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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

// WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{WLANMeasurementConfiguration-ExtIEs}} codec of TS 36.413.
func WLANMeasurementConfigurationExtIEsValueExtensionFieldTableCodec(table s00.WLANMeasurementConfigurationExtIEsValueExtensionTable) s14.WLANMeasurementConfigurationExtIEsExtFieldValueCodec {
	if !*s00.BridgeWLANMeasurementConfigurationExtIEsValueExtensionTableFieldBound(&table) {
		return s14.WLANMeasurementConfigurationExtIEsExtFieldValueCodec{}
	}
	return func() s14.WLANMeasurementConfigurationExtIEsExtFieldValueCodec {
		sealed := s14.WLANMeasurementConfigurationExtIEsExtFieldValueCodec{}
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldPath(&sealed) = "WLANMeasurementConfigurationExtIEsExtField"
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.WLANMeasurementConfigurationExtIEsExtField, error) {
			var field s14.WLANMeasurementConfigurationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WLANMeasurementConfigurationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WLANMeasurementConfigurationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WLANMeasurementConfigurationExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.WLANMeasurementConfigurationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.WLANMeasurementConfigurationExtIEsExtField, options aper.DecodeState) (s14.WLANMeasurementConfigurationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.WLANMeasurementConfigurationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// V2XServicesAuthorizedExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{V2XServicesAuthorized-ExtIEs}} codec of TS 36.413.
func V2XServicesAuthorizedExtIEsValueExtensionTableCodec(table s00.V2XServicesAuthorizedExtIEsValueExtensionTable, bounds aper.ListBounds) s14.V2XServicesAuthorizedExtIEsExtContainerValueCodec {
	if !*s00.BridgeV2XServicesAuthorizedExtIEsValueExtensionTableFieldBound(&table) {
		return s14.V2XServicesAuthorizedExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.V2XServicesAuthorizedExtIEsExtContainerValueCodec {
		sealed := s14.V2XServicesAuthorizedExtIEsExtContainerValueCodec{}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldPath(&sealed) = "V2XServicesAuthorizedExtIEsExtContainer"
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.V2XServicesAuthorizedExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.V2XServicesAuthorizedExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.V2XServicesAuthorizedExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "V2XServicesAuthorizedExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "V2XServicesAuthorizedExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "V2XServicesAuthorizedExtIEsExtContainer")
			}
			return fields, nil
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.V2XServicesAuthorizedExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeV2XServicesAuthorizedExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.V2XServicesAuthorizedExtIEsExtContainer, options aper.DecodeState) (s14.V2XServicesAuthorizedExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeV2XServicesAuthorizedExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.V2XServicesAuthorizedExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeV2XServicesAuthorizedExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeV2XServicesAuthorizedExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueIEFieldTableCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) PathSwitchRequestAcknowledgeIEFieldValueCodec {
	if !*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return PathSwitchRequestAcknowledgeIEFieldValueCodec{}
	}
	return PathSwitchRequestAcknowledgeIEFieldValueCodec{path: "PathSwitchRequestAcknowledgeIEField", decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, error) {
		var field PathSwitchRequestAcknowledgeIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledgeIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEField")
		}
		return field, nil
	}, encode: func(field PathSwitchRequestAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PathSwitchRequestAcknowledgeIEField, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PathSwitchRequestAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
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

// UEContextModificationRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueIEFieldTableCodec(table s00.UEContextModificationRequestIEValueIETable) UEContextModificationRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&table) {
		return UEContextModificationRequestIEFieldValueCodec{}
	}
	return UEContextModificationRequestIEFieldValueCodec{path: "UEContextModificationRequestIEField", decode: func(data []byte, options aper.DecodeState) (UEContextModificationRequestIEField, error) {
		var field UEContextModificationRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextModificationRequestIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextModificationRequestIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextModificationRequestIEField")
		}
		return field, nil
	}, encode: func(field UEContextModificationRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEContextModificationRequestIEField, options aper.DecodeState) (UEContextModificationRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextModificationRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(&v, &s)
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

// PathSwitchRequestAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueIETableCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) PathSwitchRequestAcknowledgeIEContainerValueCodec {
	if !*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&table) {
		return PathSwitchRequestAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PathSwitchRequestAcknowledgeIEContainerValueCodec{path: "PathSwitchRequestAcknowledgeIEContainer", decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PathSwitchRequestAcknowledgeIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PathSwitchRequestAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledgeIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEContainer")
		}
		return fields, nil
	},
		encode: func(fields PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v PathSwitchRequestAcknowledgeIEContainer, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v PathSwitchRequestAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UEContextModificationRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueIETableCodec(table s00.UEContextModificationRequestIEValueIETable, bounds aper.ListBounds) UEContextModificationRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&table) {
		return UEContextModificationRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEContextModificationRequestIEContainerValueCodec{path: "UEContextModificationRequestIEContainer", decode: func(data []byte, options aper.DecodeState) (UEContextModificationRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextModificationRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextModificationRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextModificationRequestIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEContainer")
		}
		return fields, nil
	},
		encode: func(fields UEContextModificationRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEContextModificationRequestIEContainer, options aper.DecodeState) (UEContextModificationRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v UEContextModificationRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} codec of TS 36.413.
func PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable) PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{path: "PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PathSwitchRequestAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(
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

// UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationRequestIEs}} codec of TS 36.413.
func UEContextModificationRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable) UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec{path: "UEContextModificationRequestIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextModificationRequestIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextModificationRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextModificationRequestIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextModificationRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextModificationRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextModificationRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCompareS1APProtocolErrorIEContainerList(
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

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListCodec(table s00.PathSwitchRequestAcknowledgeIEValueIETable, bounds aper.ListBounds) PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := PathSwitchRequestAcknowledgeIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec{path: "PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PathSwitchRequestAcknowledgeIEField
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
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PathSwitchRequestAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEContextModificationRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationRequestIEValueProtocolIEContainerListCodec(table s00.UEContextModificationRequestIEValueIETable, bounds aper.ListBounds) UEContextModificationRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return UEContextModificationRequestIEValueProtocolIEContainerListValueCodec{path: "UEContextModificationRequestIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextModificationRequestIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextModificationRequestIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextModificationRequestIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextModificationRequestIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextModificationRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextModificationRequestIEValueProtocolIEContainerList, options aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v UEContextModificationRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// pathSwitchRequestAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[PathSwitchRequestAcknowledgeIEValue].
type PathSwitchRequestAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PathSwitchRequestAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PathSwitchRequestAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v *PathSwitchRequestAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(v *PathSwitchRequestAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextModificationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationRequestIEValue].
type UEContextModificationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEContextModificationRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEContextModificationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(v *UEContextModificationRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(v *UEContextModificationRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// v2XServicesAuthorizedExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[V2XServicesAuthorizedExtIEsValue].
type V2XServicesAuthorizedExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.V2XServicesAuthorizedExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.V2XServicesAuthorizedExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWLANMeasurementConfigurationExtIEsValueCaptureS1APProtocolExtensionField(v *s14.WLANMeasurementConfigurationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeWLANMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWLANMeasurementConfigurationExtIEsValueCompareS1APProtocolExtensionField(v *s14.WLANMeasurementConfigurationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeWLANMeasurementConfigurationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldReplay(v), *s14.BridgeWLANMeasurementConfigurationExtIEsExtFieldFieldWithoutReplay(v))
}

// V2XServicesAuthorizedAPERValue is the concrete APERValue[V2XServicesAuthorized].
type V2XServicesAuthorizedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s57.V2XServicesAuthorized

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v V2XServicesAuthorizedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v V2XServicesAuthorizedAPERValue) WithoutReplay() V2XServicesAuthorizedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeAPERValue is the concrete APERValue[PathSwitchRequestAcknowledge].
type PathSwitchRequestAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   PathSwitchRequestAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestAPERValue is the concrete APERValue[UEContextModificationRequest].
type UEContextModificationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestAPERValue) WithoutReplay() UEContextModificationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeV2XServicesAuthorizedExtIEsValueValidateS1APIEContainer(fields s14.V2XServicesAuthorizedExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s07.BridgeV2XServicesAuthorizedExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeV2XServicesAuthorizedExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeV2XServicesAuthorizedExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledgeIEValueERABIEContainerList].
type PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList) (PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type PathSwitchRequestAcknowledgeIEValueERABIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APERABIEContainerList(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APERABIEContainerList(v *PathSwitchRequestAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationRequestIEValueERABIEContainerList].
type UEContextModificationRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) New(value UEContextModificationRequestIEValueERABIEContainerList) (UEContextModificationRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextModificationRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextModificationRequestIEValueERABIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextModificationRequestIEValueCaptureS1APERABIEContainerList(v *UEContextModificationRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APERABIEContainerList(v *UEContextModificationRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEFieldValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledgeIEField].
type PathSwitchRequestAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, error)
	encode  func(PathSwitchRequestAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEField, aper.DecodeState) (PathSwitchRequestAcknowledgeIEField, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) New(value PathSwitchRequestAcknowledgeIEField) (PathSwitchRequestAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEFieldValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEFieldValueCodec is the concrete ValueCodec[UEContextModificationRequestIEField].
type UEContextModificationRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEField, error)
	encode  func(UEContextModificationRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEField, aper.DecodeState) (UEContextModificationRequestIEField, aper.Snapshot)
	compare func(UEContextModificationRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEFieldValueCodec) New(value UEContextModificationRequestIEField) (UEContextModificationRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEFieldValueCodec) EncodeAPER(value UEContextModificationRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestIEFieldValueCodec) encodeBudgetValue(value UEContextModificationRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEFieldValueCodec) encodeChanged(value UEContextModificationRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEContainerValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledgeIEContainer].
type PathSwitchRequestAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, error)
	encode  func(PathSwitchRequestAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEContainer, aper.DecodeState) (PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) New(value PathSwitchRequestAcknowledgeIEContainer) (PathSwitchRequestAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEContainerValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEContainerValueCodec is the concrete ValueCodec[UEContextModificationRequestIEContainer].
type UEContextModificationRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEContainer, error)
	encode  func(UEContextModificationRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEContainer, aper.DecodeState) (UEContextModificationRequestIEContainer, aper.Snapshot)
	compare func(UEContextModificationRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEContainerValueCodec) New(value UEContextModificationRequestIEContainer) (UEContextModificationRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEContainerValueCodec) EncodeAPER(value UEContextModificationRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestIEContainerValueCodec) encodeBudgetValue(value UEContextModificationRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEContainerValueCodec) encodeChanged(value UEContextModificationRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList].
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{PathSwitchRequestAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationRequestIEValueProtocolErrorIEContainerList].
type UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextModificationRequestIEValueProtocolErrorIEContainerList) (UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextModificationRequestIEs}} of TS 36.413: a list of information element fields.
type UEContextModificationRequestIEValueProtocolErrorIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *UEContextModificationRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolErrorIEContainerList(v *UEContextModificationRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList].
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {PathSwitchRequestAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList []PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextModificationRequestIEValueProtocolIEContainerList].
type UEContextModificationRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, error)
	encode  func(UEContextModificationRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextModificationRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) New(value UEContextModificationRequestIEValueProtocolIEContainerList) (UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextModificationRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextModificationRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextModificationRequestIEValueProtocolIEContainerList []UEContextModificationRequestIEValueProtocolIESingleContainer

func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainerList(v *UEContextModificationRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainerList(v *UEContextModificationRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestAcknowledgeIEValueERABIEContainerList].
type PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{PathSwitchRequestAcknowledgeIEs}} of TS 36.413: a single information element field.
type PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer = PathSwitchRequestAcknowledgeIEField

func BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *PathSwitchRequestAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEContextModificationRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextModificationRequestIEValueERABIEContainerList].
type UEContextModificationRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextModificationRequestIEs}} of TS 36.413: a single information element field.
type UEContextModificationRequestIEValueProtocolIESingleContainer = UEContextModificationRequestIEField

func BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIESingleContainer(v *UEContextModificationRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationRequestIEValueCompareS1APProtocolIESingleContainer(v *UEContextModificationRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PathSwitchRequestAcknowledgeIEFieldAPERValue is the concrete APERValue[PathSwitchRequestAcknowledgeIEField].
type PathSwitchRequestAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEFieldAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEFieldAPERValue is the concrete APERValue[UEContextModificationRequestIEField].
type UEContextModificationRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEFieldAPERValue) WithoutReplay() UEContextModificationRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEContainerAPERValue is the concrete APERValue[PathSwitchRequestAcknowledgeIEContainer].
type PathSwitchRequestAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEContainerAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEContainerAPERValue is the concrete APERValue[UEContextModificationRequestIEContainer].
type UEContextModificationRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEContainerAPERValue) WithoutReplay() UEContextModificationRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList].
type PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextModificationRequestIEValueProtocolErrorIEContainerList].
type UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList].
type PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PathSwitchRequestAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() PathSwitchRequestAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextModificationRequestIEValueProtocolIEContainerList].
type UEContextModificationRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextModificationRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextModificationRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APPathSwitchRequestAcknowledge(v *PathSwitchRequestAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPathSwitchRequestAcknowledge(v *PathSwitchRequestAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePathSwitchRequestAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPathSwitchRequestAcknowledgeIEValue(v *PathSwitchRequestAcknowledgeIEValue, s *aper.SemanticCapture) {
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
					s45.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(95):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULList == nil)
				if v.rowERABToBeSwitchedULList != nil {
					s29.BridgeCaptureS1APERABToBeSwitchedULList(v.rowERABToBeSwitchedULList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s29.BridgeCaptureS1APERABList(v.rowERABToBeReleasedList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s36.BridgeCaptureS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s23.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
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
					s57.BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s47.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
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
					s23.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
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
					s39.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s53.BridgeCaptureS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
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
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s23.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s23.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s28.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
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
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s47.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(341):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedList == nil)
				if v.rowERABToBeUpdatedList != nil {
					s38.BridgeCaptureS1APERABToBeUpdatedList(v.rowERABToBeUpdatedList, s)
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
func (v PathSwitchRequestAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) PathSwitchRequestAcknowledgeIEValue {
	BridgeCaptureS1APPathSwitchRequestAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPathSwitchRequestAcknowledgeIEValue(v *PathSwitchRequestAcknowledgeIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s45.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(95):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSwitchedULList == nil)
				if v.rowERABToBeSwitchedULList != nil {
					s29.BridgeCompareS1APERABToBeSwitchedULList(v.rowERABToBeSwitchedULList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(33):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeReleasedList == nil)
				if v.rowERABToBeReleasedList != nil {
					s29.BridgeCompareS1APERABList(v.rowERABToBeReleasedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(40):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityContext == nil)
				if v.rowSecurityContext != nil {
					s36.BridgeCompareS1APSecurityContext(v.rowSecurityContext, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s26.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s23.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s08.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s57.BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s47.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
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
					s23.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
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
					s39.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s53.BridgeCompareS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
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
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s23.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s23.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s28.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s08.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s47.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(341):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeUpdatedList == nil)
				if v.rowERABToBeUpdatedList != nil {
					s38.BridgeCompareS1APERABToBeUpdatedList(v.rowERABToBeUpdatedList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s08.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PathSwitchRequestAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPathSwitchRequestAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEContextModificationRequest(v *UEContextModificationRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationRequest(v *UEContextModificationRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationRequestIEValue(v *UEContextModificationRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s00.BridgeCaptureS1APSecurityKey(v.rowSecurityKey, s)
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
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s45.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
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
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s47.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
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
					s22.BridgeCaptureS1APLAI(v.rowRegisteredLAI, s)
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
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s23.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
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
		case s00.ProtocolIEID(243):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationNotPossible == nil)
				if v.rowSRVCCOperationNotPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationNotPossible(v.rowSRVCCOperationNotPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s57.BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s47.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s23.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
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
					s23.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s23.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s28.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
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
func (v UEContextModificationRequestIEValue) captureSemantics(s aper.SemanticCapture) UEContextModificationRequestIEValue {
	BridgeCaptureS1APUEContextModificationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextModificationRequestIEValue(v *UEContextModificationRequestIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s08.BridgeCompareS1APSecurityKey(v.rowSecurityKey, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(106):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriberProfileIDforRFP == nil)
				if v.rowSubscriberProfileIDforRFP != nil {
					s08.BridgeCompareS1APSubscriberProfileIDforRFP(v.rowSubscriberProfileIDforRFP, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s45.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
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
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s47.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
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
					s22.BridgeCompareS1APLAI(v.rowRegisteredLAI, s)
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
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s23.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s08.BridgeCompareS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(243):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationNotPossible == nil)
				if v.rowSRVCCOperationNotPossible != nil {
					s08.BridgeCompareS1APSRVCCOperationNotPossible(v.rowSRVCCOperationNotPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s57.BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s47.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s23.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
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
					s23.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s23.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s28.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s08.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s08.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextModificationRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextModificationRequestIEValue(&v, &s)
	return s
}

// PathSwitchRequestAcknowledge represents the ASN.1 type PathSwitchRequestAcknowledge (SEQUENCE).
type PathSwitchRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PathSwitchRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationRequest represents the ASN.1 type UEContextModificationRequest (SEQUENCE).
type UEContextModificationRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      UEContextModificationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes PathSwitchRequestAcknowledge to APER format.
func (v *PathSwitchRequestAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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

// UnmarshalAPER decodes PathSwitchRequestAcknowledge from APER format.
func (v *PathSwitchRequestAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *PathSwitchRequestAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	bb.EnterComponent("PathSwitchRequestAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "PathSwitchRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "PathSwitchRequestAcknowledge")
	}
	v.perPadding = padding
	return nil
}
func (v *PathSwitchRequestAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PathSwitchRequestAcknowledge{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PathSwitchRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PathSwitchRequestAcknowledgeIEField
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes UEContextModificationRequest to APER format.
func (v *UEContextModificationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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

// UnmarshalAPER decodes UEContextModificationRequest from APER format.
func (v *UEContextModificationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEContextModificationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	bb.EnterComponent("UEContextModificationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationRequest")
	}
	v.perPadding = padding
	return nil
}
func (v *UEContextModificationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(UEContextModificationRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem UEContextModificationRequestIEField
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PathSwitchRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "PathSwitchRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PathSwitchRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PathSwitchRequestAcknowledge) WithoutReplay() PathSwitchRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PathSwitchRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationRequest) WithoutReplay() UEContextModificationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PathSwitchRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PathSwitchRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PathSwitchRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PathSwitchRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PathSwitchRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PathSwitchRequestAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPathSwitchRequestAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PathSwitchRequestAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func (v *PathSwitchRequestAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func (v *PathSwitchRequestAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPathSwitchRequestAcknowledge(v, &s)
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
func (v *PathSwitchRequestAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PathSwitchRequestAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationRequest")
}
func (v *UEContextModificationRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationRequest")
}
func (v *UEContextModificationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationRequest(v, &s)
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
func (v *UEContextModificationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PathSwitchRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PathSwitchRequestAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PathSwitchRequestAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPathSwitchRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PathSwitchRequestAcknowledge{}
		return report, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PathSwitchRequestAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationRequest{}
		return report, aper.OperationError(err, "UEContextModificationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationRequest")
}

type PathSwitchRequestAcknowledgeIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowENBUES1APID                            *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate              *s45.UEAggregateMaximumBitrate
	rowERABToBeSwitchedULList                 *s20.ERABToBeSwitchedULList
	rowERABToBeReleasedList                   *s19.ERABList
	rowSecurityContext                        *s36.SecurityContext
	rowCriticalityDiagnostics                 *s26.CriticalityDiagnostics
	rowMMEUES1APID2                           *s00.MMEUES1APID
	rowCSGMembershipStatus                    *s00.CSGMembershipStatus
	rowProSeAuthorized                        *s23.ProSeAuthorized
	rowUEUserPlaneCIoTSupportIndicator        *s00.UEUserPlaneCIoTSupportIndicator
	rowV2XServicesAuthorized                  *s57.V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate      *s47.UESidelinkAggregateMaximumBitrate
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowNRUESecurityCapabilities               *s23.NRUESecurityCapabilities
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowAerialUEsubscriptionInformation        *s00.AerialUEsubscriptionInformation
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowSubscriptionBasedUEDifferentiationInfo *s39.SubscriptionBasedUEDifferentiationInfo
	rowHandoverRestrictionList                *s53.HandoverRestrictionList
	rowAdditionalRRMPriorityIndex             *s00.AdditionalRRMPriorityIndex
	rowNRV2XServicesAuthorized                *s23.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate    *s23.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                       *s28.PC5QoSParameters
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowUESecurityCapabilities                 *s47.UESecurityCapabilities
	rowERABToBeUpdatedList                    *s37.ERABToBeUpdatedList
	rowTimeRefDistribution                    *s00.TimeRefDistribution
}

func (v PathSwitchRequestAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(95):
		return v.rowERABToBeSwitchedULList != nil
	case s00.ProtocolIEID(33):
		return v.rowERABToBeReleasedList != nil
	case s00.ProtocolIEID(40):
		return v.rowSecurityContext != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(158):
		return v.rowMMEUES1APID2 != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
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
	case s00.ProtocolIEID(41):
		return v.rowHandoverRestrictionList != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(306):
		return v.rowNRV2XServicesAuthorized != nil
	case s00.ProtocolIEID(307):
		return v.rowNRUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(308):
		return v.rowPC5QoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(341):
		return v.rowERABToBeUpdatedList != nil
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PathSwitchRequestAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *PathSwitchRequestAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PathSwitchRequestAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs"}}
}
func (PathSwitchRequestAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(95):
		return aper.UnknownSelector
	case s00.ProtocolIEID(33):
		return aper.UnknownSelector
	case s00.ProtocolIEID(40):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
		return aper.UnknownSelector
	case s00.ProtocolIEID(158):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
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
	case s00.ProtocolIEID(41):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(306):
		return aper.UnknownSelector
	case s00.ProtocolIEID(307):
		return aper.UnknownSelector
	case s00.ProtocolIEID(308):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(341):
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
	case s00.ProtocolIEID(24):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUEaggregateMaximumBitrate() (*s45.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeSwitchedULList returns the selected ERABToBeSwitchedULList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeSwitchedULList() (*s20.ERABToBeSwitchedULList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(95) || v.rowERABToBeSwitchedULList == nil {
		return nil, false
	}
	return v.rowERABToBeSwitchedULList, true
}

// AsERABToBeReleasedList returns the selected ERABToBeReleasedList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeReleasedList() (*s19.ERABList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(33) || v.rowERABToBeReleasedList == nil {
		return nil, false
	}
	return v.rowERABToBeReleasedList, true
}

// AsSecurityContext returns the selected SecurityContext value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsSecurityContext() (*s36.SecurityContext, bool) {
	if v == nil || v.id != s00.ProtocolIEID(40) || v.rowSecurityContext == nil {
		return nil, false
	}
	return v.rowSecurityContext, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCriticalityDiagnostics() (*s26.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsMMEUES1APID2 returns the selected MMEUES1APID2 value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsMMEUES1APID2() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(158) || v.rowMMEUES1APID2 == nil {
		return nil, false
	}
	return v.rowMMEUES1APID2, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsProSeAuthorized returns the selected ProSeAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsProSeAuthorized() (*s23.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}

// AsUEUserPlaneCIoTSupportIndicator returns the selected UEUserPlaneCIoTSupportIndicator value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUEUserPlaneCIoTSupportIndicator() (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(241) || v.rowUEUserPlaneCIoTSupportIndicator == nil {
		return nil, false
	}
	return v.rowUEUserPlaneCIoTSupportIndicator, true
}

// AsV2XServicesAuthorized returns the selected V2XServicesAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsV2XServicesAuthorized() (*s57.V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}

// AsUESidelinkAggregateMaximumBitrate returns the selected UESidelinkAggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUESidelinkAggregateMaximumBitrate() (*s47.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRUESecurityCapabilities() (*s23.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsAerialUEsubscriptionInformation returns the selected AerialUEsubscriptionInformation value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s39.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsHandoverRestrictionList returns the selected HandoverRestrictionList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsHandoverRestrictionList() (*s53.HandoverRestrictionList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(41) || v.rowHandoverRestrictionList == nil {
		return nil, false
	}
	return v.rowHandoverRestrictionList, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsNRV2XServicesAuthorized returns the selected NRV2XServicesAuthorized value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRV2XServicesAuthorized() (*s23.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}

// AsNRUESidelinkAggregateMaximumBitrate returns the selected NRUESidelinkAggregateMaximumBitrate value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s23.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}

// AsPC5QoSParameters returns the selected PC5QoSParameters value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsPC5QoSParameters() (*s28.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsUESecurityCapabilities() (*s47.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsERABToBeUpdatedList returns the selected ERABToBeUpdatedList value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsERABToBeUpdatedList() (*s37.ERABToBeUpdatedList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(341) || v.rowERABToBeUpdatedList == nil {
		return nil, false
	}
	return v.rowERABToBeUpdatedList, true
}

// AsTimeRefDistribution returns the selected TimeRefDistribution value of PathSwitchRequestAcknowledgeIEValue and reports whether that alternative is active.
func (v *PathSwitchRequestAcknowledgeIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v PathSwitchRequestAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PathSwitchRequestAcknowledgeIEValue, error) {
	out := PathSwitchRequestAcknowledgeIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
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
		var value s45.UEAggregateMaximumBitrate
		child := scope
		if err := s45.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s45.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s45.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s45.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s45.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(95):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s51.BridgeUnmarshalAPERERABToBeSwitchedULListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSwitchedULList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSwitchedULList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(33):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s49.BridgeUnmarshalAPERERABListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeReleasedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeReleasedList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(40):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s36.SecurityContext
		child := scope
		if err := s36.BridgeSecurityContextMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SecurityContext:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SecurityContext")
		if err != nil {
			return out, err
		}
		*s36.BridgeSecurityContextFieldPerPadding(&value) = padding
		*s36.BridgeSecurityContextFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeSecurityContextFieldReceivedBytes(&value))
		*s36.BridgeSecurityContextFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSecurityContext = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.CriticalityDiagnostics
		child := scope
		if err := s26.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s26.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s26.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s26.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(158):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID2:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID2 = &value
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
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.ProSeAuthorized
		child := scope
		if err := s23.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s23.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s23.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s23.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
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
		var value s57.V2XServicesAuthorized
		child := scope
		if err := s57.BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s57.BridgeV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s57.BridgeV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s57.BridgeV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s57.BridgeV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s47.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s47.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
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
		var value s23.NRUESecurityCapabilities
		child := scope
		if err := s23.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s23.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s23.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
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
		var value s39.SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := s39.BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(&value) = padding
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(&value) = true
		raw.RetainContents(s39.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(&value))
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(41):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s53.HandoverRestrictionList
		child := scope
		if err := s53.BridgeHandoverRestrictionListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "HandoverRestrictionList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRestrictionList")
		if err != nil {
			return out, err
		}
		*s53.BridgeHandoverRestrictionListFieldPerPadding(&value) = padding
		*s53.BridgeHandoverRestrictionListFieldReceived(&value) = true
		raw.RetainContents(s53.BridgeHandoverRestrictionListFieldReceivedBytes(&value))
		*s53.BridgeHandoverRestrictionListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowHandoverRestrictionList = &value
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
	case s00.ProtocolIEID(306):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.NRV2XServicesAuthorized
		child := scope
		if err := s23.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s23.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s23.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s23.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.PC5QoSParameters
		child := scope
		if err := s28.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s28.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s28.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s28.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s28.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
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
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s47.UESecurityCapabilities
		child := scope
		if err := s47.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s47.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s47.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s47.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s47.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(341):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s51.BridgeUnmarshalAPERERABToBeUpdatedListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeUpdatedList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeUpdatedList = &value
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
func (v PathSwitchRequestAcknowledgeIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v PathSwitchRequestAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s45.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(95):
		if v.rowERABToBeSwitchedULList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeSwitchedULList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s51.ERABToBeSwitchedULListComplete{Value: *v.rowERABToBeSwitchedULList}
		candidate, err := s51.BridgeERABToBeSwitchedULListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(33):
		if v.rowERABToBeReleasedList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeReleasedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s49.ERABListComplete{Value: *v.rowERABToBeReleasedList}
		candidate, err := s49.BridgeERABListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(40):
		if v.rowSecurityContext == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-SecurityContext:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s36.BridgeSecurityContextMethodMarshalAPERBudget(v.rowSecurityContext, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(158):
		if v.rowMMEUES1APID2 == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID-2:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID2), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CSGMembershipStatus:")
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
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(241):
		if v.rowUEUserPlaneCIoTSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UEUserPlaneCIoTSupportIndicator:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s57.BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s47.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-EnhancedCoverageRestricted:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-CE-ModeBRestricted:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-AerialUEsubscriptionInformation:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-PendingDataIndication:")
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
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s39.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(41):
		if v.rowHandoverRestrictionList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-HandoverRestrictionList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s53.BridgeHandoverRestrictionListMethodMarshalAPERBudget(v.rowHandoverRestrictionList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-AdditionalRRMPriorityIndex:")
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
	case s00.ProtocolIEID(306):
		if v.rowNRV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s47.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(341):
		if v.rowERABToBeUpdatedList == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-E-RABToBeUpdatedList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s51.ERABToBeUpdatedListComplete{Value: *v.rowERABToBeUpdatedList}
		candidate, err := s51.BridgeERABToBeUpdatedListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "PathSwitchRequestAcknowledgeIEs.id-TimeRefDistribution:")
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
		return nil, fmt.Errorf("%s id %d has no value", "PathSwitchRequestAcknowledgeIEValue:", v.id)
	}
}

type UEContextModificationRequestIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowMMEUES1APID                         *s00.MMEUES1APID
	rowENBUES1APID                         *s00.ENBUES1APID
	rowSecurityKey                         *s00.SecurityKey
	rowSubscriberProfileIDforRFP           *s00.SubscriberProfileIDforRFP
	rowUEaggregateMaximumBitrate           *s45.UEAggregateMaximumBitrate
	rowCSFallbackIndicator                 *s00.CSFallbackIndicator
	rowUESecurityCapabilities              *s47.UESecurityCapabilities
	rowCSGMembershipStatus                 *s00.CSGMembershipStatus
	rowRegisteredLAI                       *s22.LAI
	rowAdditionalCSFallbackIndicator       *s00.AdditionalCSFallbackIndicator
	rowProSeAuthorized                     *s23.ProSeAuthorized
	rowSRVCCOperationPossible              *s00.SRVCCOperationPossible
	rowSRVCCOperationNotPossible           *s00.SRVCCOperationNotPossible
	rowV2XServicesAuthorized               *s57.V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate   *s47.UESidelinkAggregateMaximumBitrate
	rowNRUESecurityCapabilities            *s23.NRUESecurityCapabilities
	rowAerialUEsubscriptionInformation     *s00.AerialUEsubscriptionInformation
	rowAdditionalRRMPriorityIndex          *s00.AdditionalRRMPriorityIndex
	rowIABAuthorized                       *s00.IABAuthorized
	rowNRV2XServicesAuthorized             *s23.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate *s23.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                    *s28.PC5QoSParameters
	rowUERadioCapabilityID                 *s00.UERadioCapabilityID
	rowTimeRefDistribution                 *s00.TimeRefDistribution
}

func (v UEContextModificationRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(73):
		return v.rowSecurityKey != nil
	case s00.ProtocolIEID(106):
		return v.rowSubscriberProfileIDforRFP != nil
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(108):
		return v.rowCSFallbackIndicator != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(159):
		return v.rowRegisteredLAI != nil
	case s00.ProtocolIEID(187):
		return v.rowAdditionalCSFallbackIndicator != nil
	case s00.ProtocolIEID(195):
		return v.rowProSeAuthorized != nil
	case s00.ProtocolIEID(124):
		return v.rowSRVCCOperationPossible != nil
	case s00.ProtocolIEID(243):
		return v.rowSRVCCOperationNotPossible != nil
	case s00.ProtocolIEID(240):
		return v.rowV2XServicesAuthorized != nil
	case s00.ProtocolIEID(248):
		return v.rowUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(277):
		return v.rowAerialUEsubscriptionInformation != nil
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
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextModificationRequestIEValue and reports whether the opaque alternative is selected.
func (v *UEContextModificationRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextModificationRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs"}}
}
func (UEContextModificationRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(73):
		return aper.UnknownSelector
	case s00.ProtocolIEID(106):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(108):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(159):
		return aper.UnknownSelector
	case s00.ProtocolIEID(187):
		return aper.UnknownSelector
	case s00.ProtocolIEID(195):
		return aper.UnknownSelector
	case s00.ProtocolIEID(124):
		return aper.UnknownSelector
	case s00.ProtocolIEID(243):
		return aper.UnknownSelector
	case s00.ProtocolIEID(240):
		return aper.UnknownSelector
	case s00.ProtocolIEID(248):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(277):
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
	case s00.ProtocolIEID(24):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
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
	case s00.ProtocolIEID(158):
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
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
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
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsSecurityKey returns the selected SecurityKey value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSecurityKey() (*s00.SecurityKey, bool) {
	if v == nil || v.id != s00.ProtocolIEID(73) || v.rowSecurityKey == nil {
		return nil, false
	}
	return v.rowSecurityKey, true
}

// AsSubscriberProfileIDforRFP returns the selected SubscriberProfileIDforRFP value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSubscriberProfileIDforRFP() (*s00.SubscriberProfileIDforRFP, bool) {
	if v == nil || v.id != s00.ProtocolIEID(106) || v.rowSubscriberProfileIDforRFP == nil {
		return nil, false
	}
	return v.rowSubscriberProfileIDforRFP, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUEaggregateMaximumBitrate() (*s45.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsCSFallbackIndicator returns the selected CSFallbackIndicator value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsCSFallbackIndicator() (*s00.CSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(108) || v.rowCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowCSFallbackIndicator, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUESecurityCapabilities() (*s47.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsRegisteredLAI returns the selected RegisteredLAI value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsRegisteredLAI() (*s22.LAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(159) || v.rowRegisteredLAI == nil {
		return nil, false
	}
	return v.rowRegisteredLAI, true
}

// AsAdditionalCSFallbackIndicator returns the selected AdditionalCSFallbackIndicator value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAdditionalCSFallbackIndicator() (*s00.AdditionalCSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(187) || v.rowAdditionalCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowAdditionalCSFallbackIndicator, true
}

// AsProSeAuthorized returns the selected ProSeAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsProSeAuthorized() (*s23.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}

// AsSRVCCOperationPossible returns the selected SRVCCOperationPossible value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSRVCCOperationPossible() (*s00.SRVCCOperationPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(124) || v.rowSRVCCOperationPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationPossible, true
}

// AsSRVCCOperationNotPossible returns the selected SRVCCOperationNotPossible value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsSRVCCOperationNotPossible() (*s00.SRVCCOperationNotPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(243) || v.rowSRVCCOperationNotPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationNotPossible, true
}

// AsV2XServicesAuthorized returns the selected V2XServicesAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsV2XServicesAuthorized() (*s57.V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}

// AsUESidelinkAggregateMaximumBitrate returns the selected UESidelinkAggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUESidelinkAggregateMaximumBitrate() (*s47.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRUESecurityCapabilities() (*s23.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsAerialUEsubscriptionInformation returns the selected AerialUEsubscriptionInformation value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsIABAuthorized returns the selected IABAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsIABAuthorized() (*s00.IABAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(301) || v.rowIABAuthorized == nil {
		return nil, false
	}
	return v.rowIABAuthorized, true
}

// AsNRV2XServicesAuthorized returns the selected NRV2XServicesAuthorized value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRV2XServicesAuthorized() (*s23.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}

// AsNRUESidelinkAggregateMaximumBitrate returns the selected NRUESidelinkAggregateMaximumBitrate value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s23.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}

// AsPC5QoSParameters returns the selected PC5QoSParameters value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsPC5QoSParameters() (*s28.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsTimeRefDistribution returns the selected TimeRefDistribution value of UEContextModificationRequestIEValue and reports whether that alternative is active.
func (v *UEContextModificationRequestIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v UEContextModificationRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextModificationRequestIEValue, error) {
	out := UEContextModificationRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
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
	case s00.ProtocolIEID(106):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(256), false)
		value := s00.SubscriberProfileIDforRFP(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SubscriberProfileIDforRFP:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSubscriberProfileIDforRFP = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s45.UEAggregateMaximumBitrate
		child := scope
		if err := s45.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s45.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s45.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s45.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s45.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
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
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s47.UESecurityCapabilities
		child := scope
		if err := s47.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s47.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s47.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s47.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s47.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
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
		var value s22.LAI
		child := scope
		if err := s22.BridgeLAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RegisteredLAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LAI")
		if err != nil {
			return out, err
		}
		*s22.BridgeLAIFieldPerPadding(&value) = padding
		*s22.BridgeLAIFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeLAIFieldReceivedBytes(&value))
		*s22.BridgeLAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRegisteredLAI = &value
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
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.ProSeAuthorized
		child := scope
		if err := s23.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s23.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s23.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s23.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowProSeAuthorized = &value
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
	case s00.ProtocolIEID(243):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCOperationNotPossible"})
		value := s00.SRVCCOperationNotPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCOperationNotPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCOperationNotPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(240):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s57.V2XServicesAuthorized
		child := scope
		if err := s57.BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s57.BridgeV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s57.BridgeV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s57.BridgeV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s57.BridgeV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s47.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s47.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s47.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(269):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.NRUESecurityCapabilities
		child := scope
		if err := s23.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s23.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s23.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESecurityCapabilities = &value
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
		var value s23.NRV2XServicesAuthorized
		child := scope
		if err := s23.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s23.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s23.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s23.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.PC5QoSParameters
		child := scope
		if err := s28.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s28.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s28.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s28.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s28.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
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
func (v UEContextModificationRequestIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEContextModificationRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(73):
		if v.rowSecurityKey == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SecurityKey:")
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
	case s00.ProtocolIEID(106):
		if v.rowSubscriberProfileIDforRFP == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SubscriberProfileIDforRFP:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowSubscriberProfileIDforRFP), s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(256), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s45.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(108):
		if v.rowCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-CSFallbackIndicator:")
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
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s47.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-CSGMembershipStatus:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-RegisteredLAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeLAIMethodMarshalAPERBudget(v.rowRegisteredLAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(187):
		if v.rowAdditionalCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AdditionalCSFallbackIndicator:")
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
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(124):
		if v.rowSRVCCOperationPossible == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SRVCCOperationPossible:")
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
	case s00.ProtocolIEID(243):
		if v.rowSRVCCOperationNotPossible == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-SRVCCOperationNotPossible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCOperationNotPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(240):
		if v.rowV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s57.BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s47.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(277):
		if v.rowAerialUEsubscriptionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AerialUEsubscriptionInformation:")
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
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-AdditionalRRMPriorityIndex:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-IAB-Authorized:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextModificationRequestIEs.id-TimeRefDistribution:")
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
		return nil, fmt.Errorf("%s id %d has no value", "UEContextModificationRequestIEValue:", v.id)
	}
}

type PathSwitchRequestAcknowledgeIETable struct{}

func PathSwitchRequestAcknowledgeIEs() PathSwitchRequestAcknowledgeIETable {
	return PathSwitchRequestAcknowledgeIETable{}
}

// ID returns the ASN.1 object-set identity of PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PathSwitchRequestAcknowledgeIETable.
func (PathSwitchRequestAcknowledgeIETable) Table() s00.PathSwitchRequestAcknowledgeIEValueIETable {
	return func() s00.PathSwitchRequestAcknowledgeIEValueIETable {
		sealed := s00.PathSwitchRequestAcknowledgeIEValueIETable{}
		*s00.BridgePathSwitchRequestAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID() PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ENBUES1APID() PathSwitchRequestAcknowledgeENBUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEaggregateMaximumBitrate() PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s45.UEAggregateMaximumBitrateValueCodec {
		sealed := s45.UEAggregateMaximumBitrateValueCodec{}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s45.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s45.UEAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s45.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s45.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s45.UEAggregateMaximumBitrate, options aper.DecodeState) (s45.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s45.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s45.UEAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s45.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeSwitchedULList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(95), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSwitchedULList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeSwitchedULList"}}}
}

// ERABToBeSwitchedULList returns the typed binding for the ERABToBeSwitchedULList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeSwitchedULList() PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding {
	return PathSwitchRequestAcknowledgeERABToBeSwitchedULListIEBinding{info: t.infoERABToBeSwitchedULList(), codec: func() s20.ERABToBeSwitchedULListValueCodec {
		sealed := s20.ERABToBeSwitchedULListValueCodec{}
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldPath(&sealed) = "ERABToBeSwitchedULList"
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ERABToBeSwitchedULList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.ERABToBeSwitchedULList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSwitchedULList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(95), raw)
			if err != nil {
				var empty s20.ERABToBeSwitchedULList
				return empty, runtime.WrapDecodePath(err, "ERABToBeSwitchedULList")
			}
			value, ok := decoded.AsERABToBeSwitchedULList()
			if !ok {
				var empty s20.ERABToBeSwitchedULList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeSwitchedULList: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldEncode(&sealed) = func(value s20.ERABToBeSwitchedULList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(95), rowERABToBeSwitchedULList: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldCapture(&sealed) = func(v s20.ERABToBeSwitchedULList, options aper.DecodeState) (s20.ERABToBeSwitchedULList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s29.BridgeCaptureS1APERABToBeSwitchedULList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldCompare(&sealed) = func(v s20.ERABToBeSwitchedULList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APERABToBeSwitchedULList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeERABToBeSwitchedULListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSwitchedULList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.ERABToBeSwitchedULList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(95), rowERABToBeSwitchedULList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s20.ERABToBeSwitchedULList, bool) {
			return value.AsERABToBeSwitchedULList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeReleasedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(33), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "E-RABList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeReleasedList"}}}
}

// ERABToBeReleasedList returns the typed binding for the ERABToBeReleasedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeReleasedList() PathSwitchRequestAcknowledgeERABListIEBinding {
	return PathSwitchRequestAcknowledgeERABListIEBinding{info: t.infoERABToBeReleasedList(), codec: func() s19.ERABListValueCodec {
		sealed := s19.ERABListValueCodec{}
		*s19.BridgeERABListValueCodecFieldPath(&sealed) = "ERABList"
		*s19.BridgeERABListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ERABList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.ERABList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(33), raw)
			if err != nil {
				var empty s19.ERABList
				return empty, runtime.WrapDecodePath(err, "ERABList")
			}
			value, ok := decoded.AsERABToBeReleasedList()
			if !ok {
				var empty s19.ERABList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeReleasedList: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeERABListValueCodecFieldEncode(&sealed) = func(value s19.ERABList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeERABListValueCodecFieldCapture(&sealed) = func(v s19.ERABList, options aper.DecodeState) (s19.ERABList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s29.BridgeCaptureS1APERABList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeERABListValueCodecFieldCompare(&sealed) = func(v s19.ERABList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s29.BridgeCompareS1APERABList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeERABListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.ERABList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(33), rowERABToBeReleasedList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s19.ERABList, bool) {
			return value.AsERABToBeReleasedList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-SecurityContext"}}}
}

// SecurityContext returns the typed binding for the SecurityContext row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SecurityContext() PathSwitchRequestAcknowledgeSecurityContextIEBinding {
	return PathSwitchRequestAcknowledgeSecurityContextIEBinding{info: t.infoSecurityContext(), codec: func() s36.SecurityContextValueCodec {
		sealed := s36.SecurityContextValueCodec{}
		*s36.BridgeSecurityContextValueCodecFieldPath(&sealed) = "SecurityContext"
		*s36.BridgeSecurityContextValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.SecurityContext, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s36.SecurityContext
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityContext")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(40), raw)
			if err != nil {
				var empty s36.SecurityContext
				return empty, runtime.WrapDecodePath(err, "SecurityContext")
			}
			value, ok := decoded.AsSecurityContext()
			if !ok {
				var empty s36.SecurityContext
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-SecurityContext: no selected value")
			}
			return *value, nil
		}
		*s36.BridgeSecurityContextValueCodecFieldEncode(&sealed) = func(value s36.SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}).encodeFresh(fresh, budget)
		}
		*s36.BridgeSecurityContextValueCodecFieldCapture(&sealed) = func(v s36.SecurityContext, options aper.DecodeState) (s36.SecurityContext, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APSecurityContext(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeSecurityContextValueCodecFieldCompare(&sealed) = func(v s36.SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APSecurityContext(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s36.BridgeSecurityContextValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s36.SecurityContext) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(40), rowSecurityContext: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s36.SecurityContext, bool) {
			return value.AsSecurityContext()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CriticalityDiagnostics() PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding {
	return PathSwitchRequestAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s26.CriticalityDiagnosticsValueCodec {
		sealed := s26.CriticalityDiagnosticsValueCodec{}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s26.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s26.CriticalityDiagnostics
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s26.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s26.CriticalityDiagnostics, options aper.DecodeState) (s26.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s26.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.CriticalityDiagnostics) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s26.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoMMEUES1APID2() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(158), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-MME-UE-S1AP-ID-2"}}}
}

// MMEUES1APID2 returns the typed binding for the MMEUES1APID2 row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) MMEUES1APID2() PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding {
	return PathSwitchRequestAcknowledgeMMEUES1APIDIEBinding{info: t.infoMMEUES1APID2(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(158), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID2()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-MME-UE-S1AP-ID-2: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID2()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CSGMembershipStatus() PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding {
	return PathSwitchRequestAcknowledgeCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGMembershipStatus) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ProSeAuthorized() PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeProSeAuthorizedIEBinding{info: t.infoProSeAuthorized(), codec: func() s23.ProSeAuthorizedValueCodec {
		sealed := s23.ProSeAuthorizedValueCodec{}
		*s23.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
		*s23.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.ProSeAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.ProSeAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(195), raw)
			if err != nil {
				var empty s23.ProSeAuthorized
				return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
			}
			value, ok := decoded.AsProSeAuthorized()
			if !ok {
				var empty s23.ProSeAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-ProSeAuthorized: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s23.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s23.ProSeAuthorized, options aper.DecodeState) (s23.ProSeAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APProSeAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s23.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APProSeAuthorized(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.ProSeAuthorized) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s23.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUEUserPlaneCIoTSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(241), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEUserPlaneCIoTSupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UEUserPlaneCIoTSupportIndicator"}}}
}

// UEUserPlaneCIoTSupportIndicator returns the typed binding for the UEUserPlaneCIoTSupportIndicator row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UEUserPlaneCIoTSupportIndicator() PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding {
	return PathSwitchRequestAcknowledgeUEUserPlaneCIoTSupportIndicatorIEBinding{info: t.infoUEUserPlaneCIoTSupportIndicator(), codec: func() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
		sealed := s02.UEUserPlaneCIoTSupportIndicatorValueCodec{}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(&sealed) = "UEUserPlaneCIoTSupportIndicator"
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEUserPlaneCIoTSupportIndicator")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(241), raw)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, runtime.WrapDecodePath(err, "UEUserPlaneCIoTSupportIndicator")
			}
			value, ok := decoded.AsUEUserPlaneCIoTSupportIndicator()
			if !ok {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UEUserPlaneCIoTSupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(&v, &s)

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
		inject: func(value s00.UEUserPlaneCIoTSupportIndicator) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
			return value.AsUEUserPlaneCIoTSupportIndicator()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) V2XServicesAuthorized() PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: V2XServicesAuthorizedValueCodec{path: "V2XServicesAuthorized",
		decode: func(data []byte, options aper.DecodeState) (s57.V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s57.V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty s57.V2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty s57.V2XServicesAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		},
		encode: func(value s57.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s57.V2XServicesAuthorized, options aper.DecodeState) (s57.V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}, compare: func(v s57.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s57.V2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
		return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}
	}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s57.V2XServicesAuthorized, bool) {
		return value.AsV2XServicesAuthorized()
	}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESidelinkAggregateMaximumBitrate() PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoUESidelinkAggregateMaximumBitrate(), codec: func() s47.UESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s47.UESidelinkAggregateMaximumBitrateValueCodec{}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.UESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(248), raw)
			if err != nil {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s47.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s47.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s47.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s47.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s47.UESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s47.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) EnhancedCoverageRestricted() PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding {
	return PathSwitchRequestAcknowledgeEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.EnhancedCoverageRestricted) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESecurityCapabilities() PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestAcknowledgeNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s23.NRUESecurityCapabilitiesValueCodec {
		sealed := s23.NRUESecurityCapabilitiesValueCodec{}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s23.NRUESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s23.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s23.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s23.NRUESecurityCapabilities, options aper.DecodeState) (s23.NRUESecurityCapabilities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s23.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRUESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s23.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) CEModeBRestricted() PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding {
	return PathSwitchRequestAcknowledgeCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CEModeBRestricted) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AerialUEsubscriptionInformation() PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding {
	return PathSwitchRequestAcknowledgeAerialUEsubscriptionInformationIEBinding{info: t.infoAerialUEsubscriptionInformation(), codec: func() s00.AerialUEsubscriptionInformationValueCodec {
		sealed := s00.AerialUEsubscriptionInformationValueCodec{}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(277), raw)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
			}
			value, ok := decoded.AsAerialUEsubscriptionInformation()
			if !ok {
				var empty s00.AerialUEsubscriptionInformation
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AerialUEsubscriptionInformation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AerialUEsubscriptionInformation) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PendingDataIndication() PathSwitchRequestAcknowledgePendingDataIndicationIEBinding {
	return PathSwitchRequestAcknowledgePendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PendingDataIndication")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, runtime.WrapDecodePath(err, "PendingDataIndication")
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.PendingDataIndication) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) SubscriptionBasedUEDifferentiationInfo() PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding {
	return PathSwitchRequestAcknowledgeSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: func() s39.SubscriptionBasedUEDifferentiationInfoValueCodec {
		sealed := s39.SubscriptionBasedUEDifferentiationInfoValueCodec{}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s39.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s39.SubscriptionBasedUEDifferentiationInfo
				return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s39.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s39.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s39.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s39.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s39.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s39.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s39.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s39.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s39.SubscriptionBasedUEDifferentiationInfo) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s39.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-HandoverRestrictionList"}}}
}

// HandoverRestrictionList returns the typed binding for the HandoverRestrictionList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) HandoverRestrictionList() PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding {
	return PathSwitchRequestAcknowledgeHandoverRestrictionListIEBinding{info: t.infoHandoverRestrictionList(), codec: func() s53.HandoverRestrictionListValueCodec {
		sealed := s53.HandoverRestrictionListValueCodec{}
		*s53.BridgeHandoverRestrictionListValueCodecFieldPath(&sealed) = "HandoverRestrictionList"
		*s53.BridgeHandoverRestrictionListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s53.HandoverRestrictionList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s53.HandoverRestrictionList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("HandoverRestrictionList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(41), raw)
			if err != nil {
				var empty s53.HandoverRestrictionList
				return empty, runtime.WrapDecodePath(err, "HandoverRestrictionList")
			}
			value, ok := decoded.AsHandoverRestrictionList()
			if !ok {
				var empty s53.HandoverRestrictionList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-HandoverRestrictionList: no selected value")
			}
			return *value, nil
		}
		*s53.BridgeHandoverRestrictionListValueCodecFieldEncode(&sealed) = func(value s53.HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}).encodeFresh(fresh, budget)
		}
		*s53.BridgeHandoverRestrictionListValueCodecFieldCapture(&sealed) = func(v s53.HandoverRestrictionList, options aper.DecodeState) (s53.HandoverRestrictionList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s53.BridgeCaptureS1APHandoverRestrictionList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s53.BridgeHandoverRestrictionListValueCodecFieldCompare(&sealed) = func(v s53.HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s53.BridgeCompareS1APHandoverRestrictionList(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s53.BridgeHandoverRestrictionListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s53.HandoverRestrictionList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s53.HandoverRestrictionList, bool) {
			return value.AsHandoverRestrictionList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) AdditionalRRMPriorityIndex() PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding {
	return PathSwitchRequestAcknowledgeAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AdditionalRRMPriorityIndex) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRV2XServicesAuthorized() PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding {
	return PathSwitchRequestAcknowledgeNRV2XServicesAuthorizedIEBinding{info: t.infoNRV2XServicesAuthorized(), codec: func() s23.NRV2XServicesAuthorizedValueCodec {
		sealed := s23.NRV2XServicesAuthorizedValueCodec{}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRV2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRV2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(306), raw)
			if err != nil {
				var empty s23.NRV2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
			}
			value, ok := decoded.AsNRV2XServicesAuthorized()
			if !ok {
				var empty s23.NRV2XServicesAuthorized
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRV2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s23.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s23.NRV2XServicesAuthorized, options aper.DecodeState) (s23.NRV2XServicesAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s23.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRV2XServicesAuthorized) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s23.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NRUESidelinkAggregateMaximumBitrate() PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding {
	return PathSwitchRequestAcknowledgeNRUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoNRUESidelinkAggregateMaximumBitrate(), codec: func() s23.NRUESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s23.NRUESidelinkAggregateMaximumBitrateValueCodec{}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRUESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(307), raw)
			if err != nil {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s23.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s23.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s23.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s23.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRUESidelinkAggregateMaximumBitrate) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s23.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) PC5QoSParameters() PathSwitchRequestAcknowledgePC5QoSParametersIEBinding {
	return PathSwitchRequestAcknowledgePC5QoSParametersIEBinding{info: t.infoPC5QoSParameters(), codec: func() s28.PC5QoSParametersValueCodec {
		sealed := s28.PC5QoSParametersValueCodec{}
		*s28.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
		*s28.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.PC5QoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.PC5QoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(308), raw)
			if err != nil {
				var empty s28.PC5QoSParameters
				return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
			}
			value, ok := decoded.AsPC5QoSParameters()
			if !ok {
				var empty s28.PC5QoSParameters
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-PC5QoSParameters: no selected value")
			}
			return *value, nil
		}
		*s28.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s28.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s28.PC5QoSParameters, options aper.DecodeState) (s28.PC5QoSParameters, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s28.BridgeCaptureS1APPC5QoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s28.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APPC5QoSParameters(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s28.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.PC5QoSParameters) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s28.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UERadioCapabilityID() PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding {
	return PathSwitchRequestAcknowledgeUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APUERadioCapabilityID(&v, &s)
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
		inject: func(value s00.UERadioCapabilityID) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) UESecurityCapabilities() PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding {
	return PathSwitchRequestAcknowledgeUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s47.UESecurityCapabilitiesValueCodec {
		sealed := s47.UESecurityCapabilitiesValueCodec{}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s47.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s47.UESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s47.UESecurityCapabilities
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s47.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s47.UESecurityCapabilities, options aper.DecodeState) (s47.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s47.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s47.UESecurityCapabilities) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s47.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoERABToBeUpdatedList() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(341), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeUpdatedList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-E-RABToBeUpdatedList"}}}
}

// ERABToBeUpdatedList returns the typed binding for the ERABToBeUpdatedList row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) ERABToBeUpdatedList() PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding {
	return PathSwitchRequestAcknowledgeERABToBeUpdatedListIEBinding{info: t.infoERABToBeUpdatedList(), codec: func() s37.ERABToBeUpdatedListValueCodec {
		sealed := s37.ERABToBeUpdatedListValueCodec{}
		*s37.BridgeERABToBeUpdatedListValueCodecFieldPath(&sealed) = "ERABToBeUpdatedList"
		*s37.BridgeERABToBeUpdatedListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.ERABToBeUpdatedList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.ERABToBeUpdatedList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeUpdatedList")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(341), raw)
			if err != nil {
				var empty s37.ERABToBeUpdatedList
				return empty, runtime.WrapDecodePath(err, "ERABToBeUpdatedList")
			}
			value, ok := decoded.AsERABToBeUpdatedList()
			if !ok {
				var empty s37.ERABToBeUpdatedList
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-E-RABToBeUpdatedList: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeERABToBeUpdatedListValueCodecFieldEncode(&sealed) = func(value s37.ERABToBeUpdatedList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(341), rowERABToBeUpdatedList: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeERABToBeUpdatedListValueCodecFieldCapture(&sealed) = func(v s37.ERABToBeUpdatedList, options aper.DecodeState) (s37.ERABToBeUpdatedList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s38.BridgeCaptureS1APERABToBeUpdatedList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeERABToBeUpdatedListValueCodecFieldCompare(&sealed) = func(v s37.ERABToBeUpdatedList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s38.BridgeCompareS1APERABToBeUpdatedList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeERABToBeUpdatedListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeUpdatedList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.ERABToBeUpdatedList) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(341), rowERABToBeUpdatedList: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s37.ERABToBeUpdatedList, bool) {
			return value.AsERABToBeUpdatedList()
		}}
}
func (PathSwitchRequestAcknowledgeIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: PathSwitchRequestAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PathSwitchRequestAcknowledgeIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) TimeRefDistribution() PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding {
	return PathSwitchRequestAcknowledgeTimeRefDistributionIEBinding{info: t.infoTimeRefDistribution(), codec: func() s02.TimeRefDistributionValueCodec {
		sealed := s02.TimeRefDistributionValueCodec{}
		*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
		*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
			var zero PathSwitchRequestAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(355), raw)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
			}
			value, ok := decoded.AsTimeRefDistribution()
			if !ok {
				var empty s00.TimeRefDistribution
				return empty, fmt.Errorf("binding PathSwitchRequestAcknowledgeIEs.id-TimeRefDistribution: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APTimeRefDistribution(&v, &s)
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
		inject: func(value s00.TimeRefDistribution) PathSwitchRequestAcknowledgeIEValue {
			return PathSwitchRequestAcknowledgeIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}
		}, get: func(value *PathSwitchRequestAcknowledgeIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PathSwitchRequestAcknowledgeIETable.
func (t PathSwitchRequestAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PathSwitchRequestAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(95):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSwitchedULList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(33):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeReleasedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(158):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID-2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(241):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEUserPlaneCIoTSupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(341):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeUpdatedList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PathSwitchRequestAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return PathSwitchRequestAcknowledgeIEField{Id: id, Criticality: criticality, Value: PathSwitchRequestAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextModificationRequestIETable struct{}

func UEContextModificationRequestIEs() UEContextModificationRequestIETable {
	return UEContextModificationRequestIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextModificationRequestIETable.
func (UEContextModificationRequestIETable) Table() s00.UEContextModificationRequestIEValueIETable {
	return func() s00.UEContextModificationRequestIEValueIETable {
		sealed := s00.UEContextModificationRequestIEValueIETable{}
		*s00.BridgeUEContextModificationRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextModificationRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) MMEUES1APID() UEContextModificationRequestMMEUES1APIDIEBinding {
	return UEContextModificationRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID()
		}}
}
func (UEContextModificationRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ENBUES1APID() UEContextModificationRequestENBUES1APIDIEBinding {
	return UEContextModificationRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.ENBUES1APID, bool) {
			return value.AsENBUES1APID()
		}}
}
func (UEContextModificationRequestIETable) infoSecurityKey() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(73), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityKey"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SecurityKey"}}}
}

// SecurityKey returns the typed binding for the SecurityKey row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SecurityKey() UEContextModificationRequestSecurityKeyIEBinding {
	return UEContextModificationRequestSecurityKeyIEBinding{info: t.infoSecurityKey(), codec: func() s02.SecurityKeyValueCodec {
		sealed := s02.SecurityKeyValueCodec{}
		*s02.BridgeSecurityKeyValueCodecFieldPath(&sealed) = "SecurityKey"
		*s02.BridgeSecurityKeyValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecurityKey, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SecurityKey
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityKey")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(73), raw)
			if err != nil {
				var empty s00.SecurityKey
				return empty, runtime.WrapDecodePath(err, "SecurityKey")
			}
			value, ok := decoded.AsSecurityKey()
			if !ok {
				var empty s00.SecurityKey
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SecurityKey: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSecurityKeyValueCodecFieldEncode(&sealed) = func(value s00.SecurityKey, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSecurityKeyValueCodecFieldCapture(&sealed) = func(v s00.SecurityKey, options aper.DecodeState) (s00.SecurityKey, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSecurityKey(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSecurityKeyValueCodecFieldCompare(&sealed) = func(v s00.SecurityKey, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSecurityKey(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeSecurityKeyValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityKey"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SecurityKey) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SecurityKey, bool) {
			return value.AsSecurityKey()
		}}
}
func (UEContextModificationRequestIETable) infoSubscriberProfileIDforRFP() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(106), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SubscriberProfileIDforRFP"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SubscriberProfileIDforRFP"}}}
}

// SubscriberProfileIDforRFP returns the typed binding for the SubscriberProfileIDforRFP row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SubscriberProfileIDforRFP() UEContextModificationRequestSubscriberProfileIDforRFPIEBinding {
	return UEContextModificationRequestSubscriberProfileIDforRFPIEBinding{info: t.infoSubscriberProfileIDforRFP(), codec: func() s02.SubscriberProfileIDforRFPValueCodec {
		sealed := s02.SubscriberProfileIDforRFPValueCodec{}
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldPath(&sealed) = "SubscriberProfileIDforRFP"
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriberProfileIDforRFP")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(106), raw)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, runtime.WrapDecodePath(err, "SubscriberProfileIDforRFP")
			}
			value, ok := decoded.AsSubscriberProfileIDforRFP()
			if !ok {
				var empty s00.SubscriberProfileIDforRFP
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SubscriberProfileIDforRFP: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&sealed) = func(value s00.SubscriberProfileIDforRFP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldCapture(&sealed) = func(v s00.SubscriberProfileIDforRFP, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSubscriberProfileIDforRFP(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldCompare(&sealed) = func(v s00.SubscriberProfileIDforRFP, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSubscriberProfileIDforRFP(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSubscriberProfileIDforRFPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriberProfileIDforRFP"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SubscriberProfileIDforRFP) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
			return value.AsSubscriberProfileIDforRFP()
		}}
}
func (UEContextModificationRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UEaggregateMaximumBitrate() UEContextModificationRequestUEAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s45.UEAggregateMaximumBitrateValueCodec {
		sealed := s45.UEAggregateMaximumBitrateValueCodec{}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s45.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s45.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s45.UEAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s45.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s45.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s45.UEAggregateMaximumBitrate, options aper.DecodeState) (s45.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s45.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s45.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s45.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s45.UEAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s45.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(108), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSFallbackIndicator"}}}
}

// CSFallbackIndicator returns the typed binding for the CSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSFallbackIndicator() UEContextModificationRequestCSFallbackIndicatorIEBinding {
	return UEContextModificationRequestCSFallbackIndicatorIEBinding{info: t.infoCSFallbackIndicator(), codec: func() s00.CSFallbackIndicatorValueCodec {
		sealed := s00.CSFallbackIndicatorValueCodec{}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldPath(&sealed) = "CSFallbackIndicator"
		*s00.BridgeCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSFallbackIndicator")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(108), raw)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, runtime.WrapDecodePath(err, "CSFallbackIndicator")
			}
			value, ok := decoded.AsCSFallbackIndicator()
			if !ok {
				var empty s00.CSFallbackIndicator
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSFallbackIndicator) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.CSFallbackIndicator, bool) {
			return value.AsCSFallbackIndicator()
		}}
}
func (UEContextModificationRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESecurityCapabilities() UEContextModificationRequestUESecurityCapabilitiesIEBinding {
	return UEContextModificationRequestUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s47.UESecurityCapabilitiesValueCodec {
		sealed := s47.UESecurityCapabilitiesValueCodec{}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s47.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s47.UESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s47.UESecurityCapabilities
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s47.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s47.UESecurityCapabilities, options aper.DecodeState) (s47.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s47.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s47.UESecurityCapabilities) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s47.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (UEContextModificationRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) CSGMembershipStatus() UEContextModificationRequestCSGMembershipStatusIEBinding {
	return UEContextModificationRequestCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGMembershipStatus) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (UEContextModificationRequestIETable) infoRegisteredLAI() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(159), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-RegisteredLAI"}}}
}

// RegisteredLAI returns the typed binding for the RegisteredLAI row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) RegisteredLAI() UEContextModificationRequestLAIIEBinding {
	return UEContextModificationRequestLAIIEBinding{info: t.infoRegisteredLAI(), codec: func() s22.LAIValueCodec {
		sealed := s22.LAIValueCodec{}
		*s22.BridgeLAIValueCodecFieldPath(&sealed) = "LAI"
		*s22.BridgeLAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.LAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LAI")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(159), raw)
			if err != nil {
				var empty s22.LAI
				return empty, runtime.WrapDecodePath(err, "LAI")
			}
			value, ok := decoded.AsRegisteredLAI()
			if !ok {
				var empty s22.LAI
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-RegisteredLAI: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeLAIValueCodecFieldEncode(&sealed) = func(value s22.LAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeLAIValueCodecFieldCapture(&sealed) = func(v s22.LAI, options aper.DecodeState) (s22.LAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APLAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s22.BridgeLAIValueCodecFieldCompare(&sealed) = func(v s22.LAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APLAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.LAI) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s22.LAI, bool) { return value.AsRegisteredLAI() }}
}
func (UEContextModificationRequestIETable) infoAdditionalCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(187), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalCSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalCSFallbackIndicator"}}}
}

// AdditionalCSFallbackIndicator returns the typed binding for the AdditionalCSFallbackIndicator row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalCSFallbackIndicator() UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding {
	return UEContextModificationRequestAdditionalCSFallbackIndicatorIEBinding{info: t.infoAdditionalCSFallbackIndicator(), codec: func() s00.AdditionalCSFallbackIndicatorValueCodec {
		sealed := s00.AdditionalCSFallbackIndicatorValueCodec{}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldPath(&sealed) = "AdditionalCSFallbackIndicator"
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalCSFallbackIndicator")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(187), raw)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, runtime.WrapDecodePath(err, "AdditionalCSFallbackIndicator")
			}
			value, ok := decoded.AsAdditionalCSFallbackIndicator()
			if !ok {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalCSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.AdditionalCSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AdditionalCSFallbackIndicator) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
			return value.AsAdditionalCSFallbackIndicator()
		}}
}
func (UEContextModificationRequestIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) ProSeAuthorized() UEContextModificationRequestProSeAuthorizedIEBinding {
	return UEContextModificationRequestProSeAuthorizedIEBinding{info: t.infoProSeAuthorized(), codec: func() s23.ProSeAuthorizedValueCodec {
		sealed := s23.ProSeAuthorizedValueCodec{}
		*s23.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
		*s23.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.ProSeAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.ProSeAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(195), raw)
			if err != nil {
				var empty s23.ProSeAuthorized
				return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
			}
			value, ok := decoded.AsProSeAuthorized()
			if !ok {
				var empty s23.ProSeAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-ProSeAuthorized: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s23.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s23.ProSeAuthorized, options aper.DecodeState) (s23.ProSeAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APProSeAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s23.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APProSeAuthorized(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s23.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.ProSeAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s23.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationPossible"}}}
}

// SRVCCOperationPossible returns the typed binding for the SRVCCOperationPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationPossible() UEContextModificationRequestSRVCCOperationPossibleIEBinding {
	return UEContextModificationRequestSRVCCOperationPossibleIEBinding{info: t.infoSRVCCOperationPossible(), codec: func() s02.SRVCCOperationPossibleValueCodec {
		sealed := s02.SRVCCOperationPossibleValueCodec{}
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCOperationPossible")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(124), raw)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, runtime.WrapDecodePath(err, "SRVCCOperationPossible")
			}
			value, ok := decoded.AsSRVCCOperationPossible()
			if !ok {
				var empty s00.SRVCCOperationPossible
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationPossible: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationPossible, options aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCOperationPossible(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSRVCCOperationPossible(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSRVCCOperationPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCOperationPossible) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}}
}
func (UEContextModificationRequestIETable) infoSRVCCOperationNotPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(243), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationNotPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-SRVCCOperationNotPossible"}}}
}

// SRVCCOperationNotPossible returns the typed binding for the SRVCCOperationNotPossible row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) SRVCCOperationNotPossible() UEContextModificationRequestSRVCCOperationNotPossibleIEBinding {
	return UEContextModificationRequestSRVCCOperationNotPossibleIEBinding{info: t.infoSRVCCOperationNotPossible(), codec: func() s02.SRVCCOperationNotPossibleValueCodec {
		sealed := s02.SRVCCOperationNotPossibleValueCodec{}
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationNotPossible"
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationNotPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationNotPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCOperationNotPossible")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(243), raw)
			if err != nil {
				var empty s00.SRVCCOperationNotPossible
				return empty, runtime.WrapDecodePath(err, "SRVCCOperationNotPossible")
			}
			value, ok := decoded.AsSRVCCOperationNotPossible()
			if !ok {
				var empty s00.SRVCCOperationNotPossible
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-SRVCCOperationNotPossible: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationNotPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(243), rowSRVCCOperationNotPossible: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationNotPossible, options aper.DecodeState) (s00.SRVCCOperationNotPossible, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCOperationNotPossible(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationNotPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSRVCCOperationNotPossible(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSRVCCOperationNotPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationNotPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCOperationNotPossible) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(243), rowSRVCCOperationNotPossible: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.SRVCCOperationNotPossible, bool) {
			return value.AsSRVCCOperationNotPossible()
		}}
}
func (UEContextModificationRequestIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) V2XServicesAuthorized() UEContextModificationRequestV2XServicesAuthorizedIEBinding {
	return UEContextModificationRequestV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: V2XServicesAuthorizedValueCodec{path: "V2XServicesAuthorized",
		decode: func(data []byte, options aper.DecodeState) (s57.V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s57.V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty s57.V2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty s57.V2XServicesAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		},
		encode: func(value s57.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s57.V2XServicesAuthorized, options aper.DecodeState) (s57.V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s57.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}, compare: func(v s57.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s57.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s57.V2XServicesAuthorized) UEContextModificationRequestIEValue {
		return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}
	}, get: func(value *UEContextModificationRequestIEValue) (*s57.V2XServicesAuthorized, bool) {
		return value.AsV2XServicesAuthorized()
	}}
}
func (UEContextModificationRequestIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UESidelinkAggregateMaximumBitrate() UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoUESidelinkAggregateMaximumBitrate(), codec: func() s47.UESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s47.UESidelinkAggregateMaximumBitrateValueCodec{}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.UESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(248), raw)
			if err != nil {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s47.UESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s47.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s47.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s47.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s47.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s47.UESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s47.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESecurityCapabilities() UEContextModificationRequestNRUESecurityCapabilitiesIEBinding {
	return UEContextModificationRequestNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s23.NRUESecurityCapabilitiesValueCodec {
		sealed := s23.NRUESecurityCapabilitiesValueCodec{}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s23.NRUESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s23.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s23.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s23.NRUESecurityCapabilities, options aper.DecodeState) (s23.NRUESecurityCapabilities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s23.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRUESecurityCapabilities) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s23.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (UEContextModificationRequestIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AerialUEsubscriptionInformation() UEContextModificationRequestAerialUEsubscriptionInformationIEBinding {
	return UEContextModificationRequestAerialUEsubscriptionInformationIEBinding{info: t.infoAerialUEsubscriptionInformation(), codec: func() s00.AerialUEsubscriptionInformationValueCodec {
		sealed := s00.AerialUEsubscriptionInformationValueCodec{}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(277), raw)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
			}
			value, ok := decoded.AsAerialUEsubscriptionInformation()
			if !ok {
				var empty s00.AerialUEsubscriptionInformation
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AerialUEsubscriptionInformation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AerialUEsubscriptionInformation) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}}
}
func (UEContextModificationRequestIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) AdditionalRRMPriorityIndex() UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding {
	return UEContextModificationRequestAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AdditionalRRMPriorityIndex) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (UEContextModificationRequestIETable) infoIABAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(301), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Authorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-IAB-Authorized"}}}
}

// IABAuthorized returns the typed binding for the IABAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) IABAuthorized() UEContextModificationRequestIABAuthorizedIEBinding {
	return UEContextModificationRequestIABAuthorizedIEBinding{info: t.infoIABAuthorized(), codec: func() s01.IABAuthorizedValueCodec {
		sealed := s01.IABAuthorizedValueCodec{}
		*s01.BridgeIABAuthorizedValueCodecFieldPath(&sealed) = "IABAuthorized"
		*s01.BridgeIABAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("IABAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(301), raw)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, runtime.WrapDecodePath(err, "IABAuthorized")
			}
			value, ok := decoded.AsIABAuthorized()
			if !ok {
				var empty s00.IABAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-IAB-Authorized: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeIABAuthorizedValueCodecFieldEncode(&sealed) = func(value s00.IABAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeIABAuthorizedValueCodecFieldCapture(&sealed) = func(v s00.IABAuthorized, options aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIABAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeIABAuthorizedValueCodecFieldCompare(&sealed) = func(v s00.IABAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIABAuthorized(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s01.BridgeIABAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IABAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.IABAuthorized, bool) {
			return value.AsIABAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRV2XServicesAuthorized() UEContextModificationRequestNRV2XServicesAuthorizedIEBinding {
	return UEContextModificationRequestNRV2XServicesAuthorizedIEBinding{info: t.infoNRV2XServicesAuthorized(), codec: func() s23.NRV2XServicesAuthorizedValueCodec {
		sealed := s23.NRV2XServicesAuthorizedValueCodec{}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRV2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRV2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(306), raw)
			if err != nil {
				var empty s23.NRV2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
			}
			value, ok := decoded.AsNRV2XServicesAuthorized()
			if !ok {
				var empty s23.NRV2XServicesAuthorized
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRV2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s23.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s23.NRV2XServicesAuthorized, options aper.DecodeState) (s23.NRV2XServicesAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s23.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRV2XServicesAuthorized) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s23.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}}
}
func (UEContextModificationRequestIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NRUESidelinkAggregateMaximumBitrate() UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
	return UEContextModificationRequestNRUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoNRUESidelinkAggregateMaximumBitrate(), codec: func() s23.NRUESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s23.NRUESidelinkAggregateMaximumBitrateValueCodec{}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NRUESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(307), raw)
			if err != nil {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s23.NRUESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s23.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s23.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s23.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s23.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NRUESidelinkAggregateMaximumBitrate) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s23.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}}
}
func (UEContextModificationRequestIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) PC5QoSParameters() UEContextModificationRequestPC5QoSParametersIEBinding {
	return UEContextModificationRequestPC5QoSParametersIEBinding{info: t.infoPC5QoSParameters(), codec: func() s28.PC5QoSParametersValueCodec {
		sealed := s28.PC5QoSParametersValueCodec{}
		*s28.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
		*s28.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.PC5QoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.PC5QoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(308), raw)
			if err != nil {
				var empty s28.PC5QoSParameters
				return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
			}
			value, ok := decoded.AsPC5QoSParameters()
			if !ok {
				var empty s28.PC5QoSParameters
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-PC5QoSParameters: no selected value")
			}
			return *value, nil
		}
		*s28.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s28.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s28.PC5QoSParameters, options aper.DecodeState) (s28.PC5QoSParameters, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s28.BridgeCaptureS1APPC5QoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s28.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APPC5QoSParameters(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s28.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.PC5QoSParameters) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s28.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}}
}
func (UEContextModificationRequestIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) UERadioCapabilityID() UEContextModificationRequestUERadioCapabilityIDIEBinding {
	return UEContextModificationRequestUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APUERadioCapabilityID(&v, &s)
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
		inject: func(value s00.UERadioCapabilityID) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (UEContextModificationRequestIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextModificationRequestIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextModificationRequestIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) TimeRefDistribution() UEContextModificationRequestTimeRefDistributionIEBinding {
	return UEContextModificationRequestTimeRefDistributionIEBinding{info: t.infoTimeRefDistribution(), codec: func() s02.TimeRefDistributionValueCodec {
		sealed := s02.TimeRefDistributionValueCodec{}
		*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
		*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
			var zero UEContextModificationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(355), raw)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
			}
			value, ok := decoded.AsTimeRefDistribution()
			if !ok {
				var empty s00.TimeRefDistribution
				return empty, fmt.Errorf("binding UEContextModificationRequestIEs.id-TimeRefDistribution: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextModificationRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}).encodeFresh(fresh, budget)
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
			s08.BridgeCompareS1APTimeRefDistribution(&v, &s)
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
		inject: func(value s00.TimeRefDistribution) UEContextModificationRequestIEValue {
			return UEContextModificationRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}
		}, get: func(value *UEContextModificationRequestIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextModificationRequestIETable.
func (t UEContextModificationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextModificationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(73):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityKey requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(106):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SubscriberProfileIDforRFP requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(108):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(159):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RegisteredLAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(187):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalCSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(243):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationNotPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(301):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Authorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return UEContextModificationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextModificationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextModificationRequestIEField{Id: id, Criticality: criticality, Value: UEContextModificationRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ERABToBeSwitchedULListCodec binds the complete APER value type.
func ERABToBeSwitchedULListCodec() s20.ERABToBeSwitchedULListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Codec()
}

// ERABToBeUpdatedListCodec binds the complete APER value type.
func ERABToBeUpdatedListCodec() s37.ERABToBeUpdatedListValueCodec {
	return PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Codec()
}

// SRVCCOperationNotPossibleCodec binds the complete APER value type.
func SRVCCOperationNotPossibleCodec() s02.SRVCCOperationNotPossibleValueCodec {
	return UEContextModificationRequestIEs().SRVCCOperationNotPossible().Codec()
}
func BridgeValidationHasValueMismatch(report s25.ValidationReport) bool {
	for _, issue := range report.Issues {
		if issue.Code == s00.ValueIDMismatch {
			return true
		}
	}
	return false
}
func BridgeValidatePrivateMessageBudget(v *s30.PrivateMessage, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PrivateMessage")
	}
	report := func() s25.ValidationReport {
		report := func() s25.ValidationReport {
			sealed := s25.ValidationReport{Complete: false}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
		s25.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "PrivateMessage.privateIEs"})
		return report
	}()
	for i, field := range v.PrivateIEs {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s25.BridgeValidationReportFieldErr(&report)
		}
		if !s29.BridgePrivateMessageIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			id := field.Id
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("PrivateMessage.privateIEs[%d].id", i))}, PrivateID: &id, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{s29.BridgePrivateMessageIEsValueMethodRule(field.Value)}})
		}
	}
	return report, nil
}
func ValidatePrivateMessage(v *s30.PrivateMessage, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PrivateMessage")
	}
	report, err := BridgeValidatePrivateMessageBudget(v, budget)
	if err == nil && !BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PrivateMessage")
}
func BridgePathSwitchRequestAcknowledgeFieldPerPadding(v *PathSwitchRequestAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePathSwitchRequestAcknowledgeFieldReceived(v *PathSwitchRequestAcknowledge) *bool {
	return &v.received
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedAbsolute(v *PathSwitchRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(v *PathSwitchRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePathSwitchRequestAcknowledgeFieldReceivedLocation(v *PathSwitchRequestAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(v *PathSwitchRequestAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldId(v *PathSwitchRequestAcknowledgeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldIsOpaque(v *PathSwitchRequestAcknowledgeIEValue) *bool {
	return &v.isOpaque
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldOpaque(v *PathSwitchRequestAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowAdditionalRRMPriorityIndex(v *PathSwitchRequestAcknowledgeIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowAerialUEsubscriptionInformation(v *PathSwitchRequestAcknowledgeIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCEModeBRestricted(v *PathSwitchRequestAcknowledgeIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCSGMembershipStatus(v *PathSwitchRequestAcknowledgeIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *PathSwitchRequestAcknowledgeIEValue) **s26.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowENBUES1APID(v *PathSwitchRequestAcknowledgeIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeReleasedList(v *PathSwitchRequestAcknowledgeIEValue) **s19.ERABList {
	return &v.rowERABToBeReleasedList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeSwitchedULList(v *PathSwitchRequestAcknowledgeIEValue) **s20.ERABToBeSwitchedULList {
	return &v.rowERABToBeSwitchedULList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowERABToBeUpdatedList(v *PathSwitchRequestAcknowledgeIEValue) **s37.ERABToBeUpdatedList {
	return &v.rowERABToBeUpdatedList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowEnhancedCoverageRestricted(v *PathSwitchRequestAcknowledgeIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowHandoverRestrictionList(v *PathSwitchRequestAcknowledgeIEValue) **s53.HandoverRestrictionList {
	return &v.rowHandoverRestrictionList
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID(v *PathSwitchRequestAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowMMEUES1APID2(v *PathSwitchRequestAcknowledgeIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID2
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESecurityCapabilities(v *PathSwitchRequestAcknowledgeIEValue) **s23.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s23.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowNRV2XServicesAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **s23.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowPC5QoSParameters(v *PathSwitchRequestAcknowledgeIEValue) **s28.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowPendingDataIndication(v *PathSwitchRequestAcknowledgeIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowProSeAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **s23.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowSecurityContext(v *PathSwitchRequestAcknowledgeIEValue) **s36.SecurityContext {
	return &v.rowSecurityContext
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *PathSwitchRequestAcknowledgeIEValue) **s39.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowTimeRefDistribution(v *PathSwitchRequestAcknowledgeIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUERadioCapabilityID(v *PathSwitchRequestAcknowledgeIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESecurityCapabilities(v *PathSwitchRequestAcknowledgeIEValue) **s47.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s47.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEUserPlaneCIoTSupportIndicator(v *PathSwitchRequestAcknowledgeIEValue) **s00.UEUserPlaneCIoTSupportIndicator {
	return &v.rowUEUserPlaneCIoTSupportIndicator
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowUEaggregateMaximumBitrate(v *PathSwitchRequestAcknowledgeIEValue) **s45.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgePathSwitchRequestAcknowledgeIEValueFieldRowV2XServicesAuthorized(v *PathSwitchRequestAcknowledgeIEValue) **s57.V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgePathSwitchRequestAcknowledgeIEValueMethodMatchesID(v PathSwitchRequestAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v *PathSwitchRequestAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERFrom(v *PathSwitchRequestAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERWithOptions(v *PathSwitchRequestAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldCapture(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, aper.DecodeState) (PathSwitchRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldCompare(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldContext(v *PathSwitchRequestAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldDecode(v *PathSwitchRequestAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (PathSwitchRequestAcknowledge, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldEncode(v *PathSwitchRequestAcknowledgeValueCodec) *func(PathSwitchRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeValueCodecFieldPath(v *PathSwitchRequestAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationRequestFieldPerPadding(v *UEContextModificationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationRequestFieldReceived(v *UEContextModificationRequest) *bool {
	return &v.received
}
func BridgeUEContextModificationRequestFieldReceivedAbsolute(v *UEContextModificationRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationRequestFieldReceivedBytes(v *UEContextModificationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationRequestFieldReceivedLocation(v *UEContextModificationRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(v *UEContextModificationRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationRequestIEValueFieldId(v *UEContextModificationRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextModificationRequestIEValueFieldIsOpaque(v *UEContextModificationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextModificationRequestIEValueFieldOpaque(v *UEContextModificationRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextModificationRequestIEValueFieldRowAdditionalCSFallbackIndicator(v *UEContextModificationRequestIEValue) **s00.AdditionalCSFallbackIndicator {
	return &v.rowAdditionalCSFallbackIndicator
}
func BridgeUEContextModificationRequestIEValueFieldRowAdditionalRRMPriorityIndex(v *UEContextModificationRequestIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeUEContextModificationRequestIEValueFieldRowAerialUEsubscriptionInformation(v *UEContextModificationRequestIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgeUEContextModificationRequestIEValueFieldRowCSFallbackIndicator(v *UEContextModificationRequestIEValue) **s00.CSFallbackIndicator {
	return &v.rowCSFallbackIndicator
}
func BridgeUEContextModificationRequestIEValueFieldRowCSGMembershipStatus(v *UEContextModificationRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeUEContextModificationRequestIEValueFieldRowENBUES1APID(v *UEContextModificationRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextModificationRequestIEValueFieldRowIABAuthorized(v *UEContextModificationRequestIEValue) **s00.IABAuthorized {
	return &v.rowIABAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowMMEUES1APID(v *UEContextModificationRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextModificationRequestIEValueFieldRowNRUESecurityCapabilities(v *UEContextModificationRequestIEValue) **s23.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgeUEContextModificationRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s23.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowNRV2XServicesAuthorized(v *UEContextModificationRequestIEValue) **s23.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowPC5QoSParameters(v *UEContextModificationRequestIEValue) **s28.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgeUEContextModificationRequestIEValueFieldRowProSeAuthorized(v *UEContextModificationRequestIEValue) **s23.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgeUEContextModificationRequestIEValueFieldRowRegisteredLAI(v *UEContextModificationRequestIEValue) **s22.LAI {
	return &v.rowRegisteredLAI
}
func BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationNotPossible(v *UEContextModificationRequestIEValue) **s00.SRVCCOperationNotPossible {
	return &v.rowSRVCCOperationNotPossible
}
func BridgeUEContextModificationRequestIEValueFieldRowSRVCCOperationPossible(v *UEContextModificationRequestIEValue) **s00.SRVCCOperationPossible {
	return &v.rowSRVCCOperationPossible
}
func BridgeUEContextModificationRequestIEValueFieldRowSecurityKey(v *UEContextModificationRequestIEValue) **s00.SecurityKey {
	return &v.rowSecurityKey
}
func BridgeUEContextModificationRequestIEValueFieldRowSubscriberProfileIDforRFP(v *UEContextModificationRequestIEValue) **s00.SubscriberProfileIDforRFP {
	return &v.rowSubscriberProfileIDforRFP
}
func BridgeUEContextModificationRequestIEValueFieldRowTimeRefDistribution(v *UEContextModificationRequestIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgeUEContextModificationRequestIEValueFieldRowUERadioCapabilityID(v *UEContextModificationRequestIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeUEContextModificationRequestIEValueFieldRowUESecurityCapabilities(v *UEContextModificationRequestIEValue) **s47.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgeUEContextModificationRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s47.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowUEaggregateMaximumBitrate(v *UEContextModificationRequestIEValue) **s45.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeUEContextModificationRequestIEValueFieldRowV2XServicesAuthorized(v *UEContextModificationRequestIEValue) **s57.V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgeUEContextModificationRequestIEValueMethodMatchesID(v UEContextModificationRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextModificationRequestMethodMarshalAPERBudget(v *UEContextModificationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationRequestMethodUnmarshalAPERFrom(v *UEContextModificationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationRequestMethodUnmarshalAPERWithOptions(v *UEContextModificationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationRequestValueCodecFieldCapture(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, aper.DecodeState) (UEContextModificationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationRequestValueCodecFieldCompare(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationRequestValueCodecFieldContext(v *UEContextModificationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationRequestValueCodecFieldDecode(v *UEContextModificationRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationRequest, error) {
	return &v.decode
}
func BridgeUEContextModificationRequestValueCodecFieldEncode(v *UEContextModificationRequestValueCodec) *func(UEContextModificationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationRequestValueCodecFieldPath(v *UEContextModificationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeV2XServicesAuthorizedValueCodecFieldCapture(v *V2XServicesAuthorizedValueCodec) *func(s57.V2XServicesAuthorized, aper.DecodeState) (s57.V2XServicesAuthorized, aper.Snapshot) {
	return &v.capture
}
func BridgeV2XServicesAuthorizedValueCodecFieldCompare(v *V2XServicesAuthorizedValueCodec) *func(s57.V2XServicesAuthorized, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeV2XServicesAuthorizedValueCodecFieldContext(v *V2XServicesAuthorizedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeV2XServicesAuthorizedValueCodecFieldDecode(v *V2XServicesAuthorizedValueCodec) *func([]byte, aper.DecodeState) (s57.V2XServicesAuthorized, error) {
	return &v.decode
}
func BridgeV2XServicesAuthorizedValueCodecFieldEncode(v *V2XServicesAuthorizedValueCodec) *func(s57.V2XServicesAuthorized, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeV2XServicesAuthorizedValueCodecFieldPath(v *V2XServicesAuthorizedValueCodec) *aper.Path {
	return &v.path
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *PathSwitchRequestAcknowledgeIEValue) Selected() (any, bool) {
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
	case 95:
		if value, ok := v.AsERABToBeSwitchedULList(); ok {
			return value, true
		}
	case 33:
		if value, ok := v.AsERABToBeReleasedList(); ok {
			return value, true
		}
	case 40:
		if value, ok := v.AsSecurityContext(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	case 158:
		if value, ok := v.AsMMEUES1APID2(); ok {
			return value, true
		}
	case 146:
		if value, ok := v.AsCSGMembershipStatus(); ok {
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
	case 41:
		if value, ok := v.AsHandoverRestrictionList(); ok {
			return value, true
		}
	case 299:
		if value, ok := v.AsAdditionalRRMPriorityIndex(); ok {
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
	case 107:
		if value, ok := v.AsUESecurityCapabilities(); ok {
			return value, true
		}
	case 341:
		if value, ok := v.AsERABToBeUpdatedList(); ok {
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
func (v *UEContextModificationRequestIEValue) Selected() (any, bool) {
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
	case 73:
		if value, ok := v.AsSecurityKey(); ok {
			return value, true
		}
	case 106:
		if value, ok := v.AsSubscriberProfileIDforRFP(); ok {
			return value, true
		}
	case 66:
		if value, ok := v.AsUEaggregateMaximumBitrate(); ok {
			return value, true
		}
	case 108:
		if value, ok := v.AsCSFallbackIndicator(); ok {
			return value, true
		}
	case 107:
		if value, ok := v.AsUESecurityCapabilities(); ok {
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
	case 187:
		if value, ok := v.AsAdditionalCSFallbackIndicator(); ok {
			return value, true
		}
	case 195:
		if value, ok := v.AsProSeAuthorized(); ok {
			return value, true
		}
	case 124:
		if value, ok := v.AsSRVCCOperationPossible(); ok {
			return value, true
		}
	case 243:
		if value, ok := v.AsSRVCCOperationNotPossible(); ok {
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
	case 269:
		if value, ok := v.AsNRUESecurityCapabilities(); ok {
			return value, true
		}
	case 277:
		if value, ok := v.AsAerialUEsubscriptionInformation(); ok {
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
	case 355:
		if value, ok := v.AsTimeRefDistribution(); ok {
			return value, true
		}
	}
	return nil, false
}
