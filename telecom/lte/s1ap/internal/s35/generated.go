// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s35 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s35

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverNotifyIEContainer is the concrete ProtocolIEContainer[HandoverNotifyIEValue].
type HandoverNotifyIEContainer []HandoverNotifyIEField

// HandoverNotifyIEField is the concrete ProtocolIEField[HandoverNotifyIEValue].
type HandoverNotifyIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverNotifyIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEField) WithoutReplay() HandoverNotifyIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverNotifyIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverNotifyIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverNotifyIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverNotifyIEField{}
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
	var zero HandoverNotifyIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// InitialUEMessageIEContainer is the concrete ProtocolIEContainer[InitialUEMessageIEValue].
type InitialUEMessageIEContainer []InitialUEMessageIEField

// InitialUEMessageIEField is the concrete ProtocolIEField[InitialUEMessageIEValue].
type InitialUEMessageIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         InitialUEMessageIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEField) WithoutReplay() InitialUEMessageIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InitialUEMessageIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InitialUEMessageIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *InitialUEMessageIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialUEMessageIEField{}
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
	var zero InitialUEMessageIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}
func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainer(v *HandoverNotifyIEContainer, s *aper.SemanticCapture) {
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
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainer(v *HandoverNotifyIEContainer, s *aper.SemanticComparison) {
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
			BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainer(v *InitialUEMessageIEContainer, s *aper.SemanticCapture) {
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
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainer(v *InitialUEMessageIEContainer, s *aper.SemanticComparison) {
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
			BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UEAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UEAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UEAppLayerMeasConfigExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UEAppLayerMeasConfigExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIESingleContainer(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIESingleContainer(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIESingleContainer(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIESingleContainer(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer = UEAssociatedLogicalS1ConnectionItemResIEField

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer = UEAssociatedLogicalS1ConnectionItemResAckIEField

// UEAppLayerMeasConfigValueCodec is the concrete ValueCodec[UEAppLayerMeasConfig].
type UEAppLayerMeasConfigValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAppLayerMeasConfig,

		error)
	encode func(UEAppLayerMeasConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAppLayerMeasConfig, aper.DecodeState,

	) (UEAppLayerMeasConfig, aper.Snapshot,

	)
	compare func(UEAppLayerMeasConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAppLayerMeasConfigValueCodec) New(value UEAppLayerMeasConfig,

) (UEAppLayerMeasConfigAPERValue, error) {
	if c.encode == nil {
		return UEAppLayerMeasConfigAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAppLayerMeasConfigAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAppLayerMeasConfigAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAppLayerMeasConfigAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAppLayerMeasConfigValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAppLayerMeasConfigAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAppLayerMeasConfigAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAppLayerMeasConfigAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAppLayerMeasConfigAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAppLayerMeasConfigAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAppLayerMeasConfigValueCodec) EncodeAPER(value UEAppLayerMeasConfigAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAppLayerMeasConfigValueCodec) encodeBudgetValue(value UEAppLayerMeasConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAppLayerMeasConfigValueCodec) encodeChanged(value UEAppLayerMeasConfig,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TunnelInformationValueCodec is the concrete ValueCodec[TunnelInformation].
type TunnelInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s34.TunnelInformation,

		error)
	encode func(s34.TunnelInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s34.TunnelInformation, aper.DecodeState,

	) (s34.TunnelInformation, aper.Snapshot,

	)
	compare func(s34.TunnelInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TunnelInformationValueCodec) New(value s34.TunnelInformation,

) (TunnelInformationAPERValue, error) {
	if c.encode == nil {
		return TunnelInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TunnelInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TunnelInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TunnelInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TunnelInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TunnelInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TunnelInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TunnelInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TunnelInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TunnelInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TunnelInformationValueCodec) EncodeAPER(value TunnelInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TunnelInformationValueCodec) encodeBudgetValue(value s34.TunnelInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TunnelInformationValueCodec) encodeChanged(value s34.TunnelInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAggregateMaximumBitrateValueCodec is the concrete ValueCodec[UEAggregateMaximumBitrate].
type UEAggregateMaximumBitrateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAggregateMaximumBitrate,

		error)
	encode func(UEAggregateMaximumBitrate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAggregateMaximumBitrate, aper.DecodeState,

	) (UEAggregateMaximumBitrate, aper.Snapshot,

	)
	compare func(UEAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAggregateMaximumBitrateValueCodec) New(value UEAggregateMaximumBitrate,

) (UEAggregateMaximumBitrateAPERValue, error) {
	if c.encode == nil {
		return UEAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAggregateMaximumBitrateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAggregateMaximumBitrateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAggregateMaximumBitrateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAggregateMaximumBitrateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAggregateMaximumBitrateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAggregateMaximumBitrateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAggregateMaximumBitrateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAggregateMaximumBitrateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAggregateMaximumBitrateValueCodec) EncodeAPER(value UEAggregateMaximumBitrateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAggregateMaximumBitrateValueCodec) encodeBudgetValue(value UEAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAggregateMaximumBitrateValueCodec) encodeChanged(value UEAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverNotifyIEValue].
type HandoverNotifyMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyMMEUES1APIDIEBinding) Get(field *HandoverNotifyIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverNotifyIEValue].
type HandoverNotifyENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyENBUES1APIDIEBinding) Get(field *HandoverNotifyIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyEUTRANCGIIEBinding is the concrete IEBinding[EUTRANCGI, HandoverNotifyIEValue].
type HandoverNotifyEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyEUTRANCGIIEBinding) Get(field *HandoverNotifyIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyTAIIEBinding is the concrete IEBinding[TAI, HandoverNotifyIEValue].
type HandoverNotifyTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s31.TAI,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s31.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyTAIIEBinding) New(value s31.TAI,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyTAIIEBinding) Get(field *HandoverNotifyIEField) (*s31.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyTunnelInformationIEBinding is the concrete IEBinding[TunnelInformation, HandoverNotifyIEValue].
type HandoverNotifyTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  TunnelInformationValueCodec
	inject func(s34.TunnelInformation,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s34.TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyTunnelInformationIEBinding) Codec() TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverNotifyTunnelInformationIEBinding) New(value s34.TunnelInformation,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyTunnelInformationIEBinding) Get(field *HandoverNotifyIEField) (*s34.TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyLHNIDIEBinding is the concrete IEBinding[LHNID, HandoverNotifyIEValue].
type HandoverNotifyLHNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LHNIDValueCodec
	inject func(s00.LHNID,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s00.LHNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyLHNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyLHNIDIEBinding) Codec() s01.LHNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyLHNIDIEBinding) New(value s00.LHNID,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLHNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyLHNIDIEBinding) Get(field *HandoverNotifyIEField) (*s00.LHNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyPSCellInformationIEBinding is the concrete IEBinding[PSCellInformation, HandoverNotifyIEValue].
type HandoverNotifyPSCellInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PSCellInformationValueCodec
	inject func(s20.PSCellInformation,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s20.PSCellInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyPSCellInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyPSCellInformationIEBinding) Codec() s20.PSCellInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverNotifyPSCellInformationIEBinding) New(value s20.PSCellInformation,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePSCellInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyPSCellInformationIEBinding) Get(field *HandoverNotifyIEField) (*s20.PSCellInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyNotifySourceeNBIEBinding is the concrete IEBinding[NotifySourceeNB, HandoverNotifyIEValue].
type HandoverNotifyNotifySourceeNBIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NotifySourceeNBValueCodec
	inject func(s00.NotifySourceeNB,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s00.NotifySourceeNB,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyNotifySourceeNBIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyNotifySourceeNBIEBinding) Codec() s01.NotifySourceeNBValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverNotifyNotifySourceeNBIEBinding) New(value s00.NotifySourceeNB,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNotifySourceeNBValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyNotifySourceeNBIEBinding) Get(field *HandoverNotifyIEField) (*s00.NotifySourceeNB,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyLTENTNTAIInformationIEBinding is the concrete IEBinding[LTENTNTAIInformation, HandoverNotifyIEValue].
type HandoverNotifyLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverNotifyLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (HandoverNotifyIEField, error) {
	if b.inject == nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverNotifyIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverNotifyIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverNotifyLTENTNTAIInformationIEBinding) Get(field *HandoverNotifyIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, InitialUEMessageIEValue].
type InitialUEMessageENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageENBUES1APIDIEBinding) Get(field *InitialUEMessageIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageNASPDUIEBinding is the concrete IEBinding[NASPDU, InitialUEMessageIEValue].
type InitialUEMessageNASPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASPDUValueCodec
	inject func(s00.NASPDU,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.NASPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageNASPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageNASPDUIEBinding) Codec() s01.NASPDUValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageNASPDUIEBinding) New(value s00.NASPDU,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageNASPDUIEBinding) Get(field *InitialUEMessageIEField) (*s00.NASPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageTAIIEBinding is the concrete IEBinding[TAI, InitialUEMessageIEValue].
type InitialUEMessageTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s31.TAI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s31.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageTAIIEBinding) New(value s31.TAI,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageTAIIEBinding) Get(field *InitialUEMessageIEField) (*s31.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageEUTRANCGIIEBinding is the concrete IEBinding[EUTRANCGI, InitialUEMessageIEValue].
type InitialUEMessageEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s17.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageEUTRANCGIIEBinding) Codec() s17.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageEUTRANCGIIEBinding) Get(field *InitialUEMessageIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageRRCEstablishmentCauseIEBinding is the concrete IEBinding[RRCEstablishmentCause, InitialUEMessageIEValue].
type InitialUEMessageRRCEstablishmentCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RRCEstablishmentCauseValueCodec
	inject func(s00.RRCEstablishmentCause,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.RRCEstablishmentCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageRRCEstablishmentCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageRRCEstablishmentCauseIEBinding) Codec() s01.RRCEstablishmentCauseValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageRRCEstablishmentCauseIEBinding) New(value s00.RRCEstablishmentCause,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageRRCEstablishmentCauseIEBinding) Get(field *InitialUEMessageIEField) (*s00.RRCEstablishmentCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageSTMSIIEBinding is the concrete IEBinding[STMSI, InitialUEMessageIEValue].
type InitialUEMessageSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s27.STMSI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s27.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageSTMSIIEBinding) New(value s27.STMSI,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageSTMSIIEBinding) Get(field *InitialUEMessageIEField) (*s27.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCSGIdIEBinding is the concrete IEBinding[CSGId, InitialUEMessageIEValue].
type InitialUEMessageCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageCSGIdIEBinding) New(value s00.CSGId,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageCSGIdIEBinding) Get(field *InitialUEMessageIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageGUMMEIIEBinding is the concrete IEBinding[GUMMEI, InitialUEMessageIEValue].
type InitialUEMessageGUMMEIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIValueCodec
	inject func(s18.GUMMEI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s18.GUMMEI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageGUMMEIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageGUMMEIIEBinding) Codec() s18.GUMMEIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageGUMMEIIEBinding) New(value s18.GUMMEI,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageGUMMEIIEBinding) Get(field *InitialUEMessageIEField) (*s18.GUMMEI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCellAccessModeIEBinding is the concrete IEBinding[CellAccessMode, InitialUEMessageIEValue].
type InitialUEMessageCellAccessModeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellAccessModeValueCodec
	inject func(s00.CellAccessMode,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.CellAccessMode,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageCellAccessModeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageCellAccessModeIEBinding) Codec() s00.CellAccessModeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageCellAccessModeIEBinding) New(value s00.CellAccessMode,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellAccessModeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageCellAccessModeIEBinding) Get(field *InitialUEMessageIEField) (*s00.CellAccessMode,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageTransportLayerAddressIEBinding is the concrete IEBinding[TransportLayerAddress, InitialUEMessageIEValue].
type InitialUEMessageTransportLayerAddressIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TransportLayerAddressValueCodec
	inject func(s00.TransportLayerAddress,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.TransportLayerAddress,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageTransportLayerAddressIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageTransportLayerAddressIEBinding) Codec() s02.TransportLayerAddressValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageTransportLayerAddressIEBinding) New(value s00.TransportLayerAddress,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageTransportLayerAddressIEBinding) Get(field *InitialUEMessageIEField) (*s00.TransportLayerAddress,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageRelayNodeIndicatorIEBinding is the concrete IEBinding[RelayNodeIndicator, InitialUEMessageIEValue].
type InitialUEMessageRelayNodeIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RelayNodeIndicatorValueCodec
	inject func(s00.RelayNodeIndicator,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.RelayNodeIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageRelayNodeIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageRelayNodeIndicatorIEBinding) Codec() s01.RelayNodeIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageRelayNodeIndicatorIEBinding) New(value s00.RelayNodeIndicator,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRelayNodeIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageRelayNodeIndicatorIEBinding) Get(field *InitialUEMessageIEField) (*s00.RelayNodeIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageGUMMEITypeIEBinding is the concrete IEBinding[GUMMEIType, InitialUEMessageIEValue].
type InitialUEMessageGUMMEITypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.GUMMEITypeValueCodec
	inject func(s00.GUMMEIType,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.GUMMEIType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageGUMMEITypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageGUMMEITypeIEBinding) Codec() s00.GUMMEITypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageGUMMEITypeIEBinding) New(value s00.GUMMEIType,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeGUMMEITypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageGUMMEITypeIEBinding) Get(field *InitialUEMessageIEField) (*s00.GUMMEIType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageTunnelInformationIEBinding is the concrete IEBinding[TunnelInformation, InitialUEMessageIEValue].
type InitialUEMessageTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  TunnelInformationValueCodec
	inject func(s34.TunnelInformation,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s34.TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageTunnelInformationIEBinding) Codec() TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageTunnelInformationIEBinding) New(value s34.TunnelInformation,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageTunnelInformationIEBinding) Get(field *InitialUEMessageIEField) (*s34.TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageLHNIDIEBinding is the concrete IEBinding[LHNID, InitialUEMessageIEValue].
type InitialUEMessageLHNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.LHNIDValueCodec
	inject func(s00.LHNID,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.LHNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageLHNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageLHNIDIEBinding) Codec() s01.LHNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageLHNIDIEBinding) New(value s00.LHNID,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeLHNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageLHNIDIEBinding) Get(field *InitialUEMessageIEField) (*s00.LHNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageMMEGroupIDIEBinding is the concrete IEBinding[MMEGroupID, InitialUEMessageIEValue].
type InitialUEMessageMMEGroupIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEGroupIDValueCodec
	inject func(s00.MMEGroupID,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.MMEGroupID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageMMEGroupIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageMMEGroupIDIEBinding) Codec() s01.MMEGroupIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageMMEGroupIDIEBinding) New(value s00.MMEGroupID,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEGroupIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageMMEGroupIDIEBinding) Get(field *InitialUEMessageIEField) (*s00.MMEGroupID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageUEUsageTypeIEBinding is the concrete IEBinding[UEUsageType, InitialUEMessageIEValue].
type InitialUEMessageUEUsageTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUsageTypeValueCodec
	inject func(s00.UEUsageType,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.UEUsageType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageUEUsageTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageUEUsageTypeIEBinding) Codec() s02.UEUsageTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageUEUsageTypeIEBinding) New(value s00.UEUsageType,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUsageTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageUEUsageTypeIEBinding) Get(field *InitialUEMessageIEField) (*s00.UEUsageType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCEModeBSupportIndicatorIEBinding is the concrete IEBinding[CEModeBSupportIndicator, InitialUEMessageIEValue].
type InitialUEMessageCEModeBSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBSupportIndicatorValueCodec
	inject func(s00.CEModeBSupportIndicator,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.CEModeBSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageCEModeBSupportIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageCEModeBSupportIndicatorIEBinding) Codec() s00.CEModeBSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageCEModeBSupportIndicatorIEBinding) New(value s00.CEModeBSupportIndicator,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageCEModeBSupportIndicatorIEBinding) Get(field *InitialUEMessageIEField) (*s00.CEModeBSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageDCNIDIEBinding is the concrete IEBinding[DCNID, InitialUEMessageIEValue].
type InitialUEMessageDCNIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DCNIDValueCodec
	inject func(s00.DCNID,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.DCNID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageDCNIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageDCNIDIEBinding) Codec() s00.DCNIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageDCNIDIEBinding) New(value s00.DCNID,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDCNIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageDCNIDIEBinding) Get(field *InitialUEMessageIEField) (*s00.DCNID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCoverageLevelIEBinding is the concrete IEBinding[CoverageLevel, InitialUEMessageIEValue].
type InitialUEMessageCoverageLevelIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CoverageLevelValueCodec
	inject func(s00.CoverageLevel,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.CoverageLevel,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageCoverageLevelIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageCoverageLevelIEBinding) Codec() s00.CoverageLevelValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageCoverageLevelIEBinding) New(value s00.CoverageLevel,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCoverageLevelValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageCoverageLevelIEBinding) Get(field *InitialUEMessageIEField) (*s00.CoverageLevel,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding is the concrete IEBinding[UEApplicationLayerMeasurementCapability, InitialUEMessageIEValue].
type InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEApplicationLayerMeasurementCapabilityValueCodec
	inject func(s00.UEApplicationLayerMeasurementCapability,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.UEApplicationLayerMeasurementCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) Codec() s02.UEApplicationLayerMeasurementCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) New(value s00.UEApplicationLayerMeasurementCapability,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) Get(field *InitialUEMessageIEField) (*s00.UEApplicationLayerMeasurementCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageEDTSessionIEBinding is the concrete IEBinding[EDTSession, InitialUEMessageIEValue].
type InitialUEMessageEDTSessionIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EDTSessionValueCodec
	inject func(s00.EDTSession,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.EDTSession,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageEDTSessionIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageEDTSessionIEBinding) Codec() s00.EDTSessionValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageEDTSessionIEBinding) New(value s00.EDTSession,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEDTSessionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageEDTSessionIEBinding) Get(field *InitialUEMessageIEField) (*s00.EDTSession,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageIABNodeIndicationIEBinding is the concrete IEBinding[IABNodeIndication, InitialUEMessageIEValue].
type InitialUEMessageIABNodeIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.IABNodeIndicationValueCodec
	inject func(s00.IABNodeIndication,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.IABNodeIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageIABNodeIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageIABNodeIndicationIEBinding) Codec() s01.IABNodeIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageIABNodeIndicationIEBinding) New(value s00.IABNodeIndication,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIABNodeIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageIABNodeIndicationIEBinding) Get(field *InitialUEMessageIEField) (*s00.IABNodeIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageLTENTNTAIInformationIEBinding is the concrete IEBinding[LTENTNTAIInformation, InitialUEMessageIEValue].
type InitialUEMessageLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageLTENTNTAIInformationIEBinding) Get(field *InitialUEMessageIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCoarseUELocationRequestedIEBinding is the concrete IEBinding[CoarseUELocationRequested, InitialUEMessageIEValue].
type InitialUEMessageCoarseUELocationRequestedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CoarseUELocationRequestedValueCodec
	inject func(s00.CoarseUELocationRequested,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s00.CoarseUELocationRequested,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageCoarseUELocationRequestedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageCoarseUELocationRequestedIEBinding) Codec() s00.CoarseUELocationRequestedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageCoarseUELocationRequestedIEBinding) New(value s00.CoarseUELocationRequested,

) (InitialUEMessageIEField, error) {
	if b.inject == nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCoarseUELocationRequestedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialUEMessageIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialUEMessageIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialUEMessageCoarseUELocationRequestedIEBinding) Get(field *InitialUEMessageIEField) (*s00.CoarseUELocationRequested,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEAssociatedLogicalS1ConnectionListResAckValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionListResAck].
type UEAssociatedLogicalS1ConnectionListResAckValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListResAck,

		error)
	encode func(UEAssociatedLogicalS1ConnectionListResAck,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionListResAck, aper.DecodeState,

	) (UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot,

	)
	compare func(UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionListResAckValueCodec) New(value UEAssociatedLogicalS1ConnectionListResAck,

) (UEAssociatedLogicalS1ConnectionListResAckAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionListResAckAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionListResAckValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResAckAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionListResAckAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionListResAckAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionListResAckValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionListResAckAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionListResAckValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionListResAck,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionListResAckValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionListResAck,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding is the concrete IEBinding[UEAssociatedLogicalS1ConnectionItem, UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding struct {
	info   s00.FieldInfo
	codec  UEAssociatedLogicalS1ConnectionItemValueCodec
	inject func(UEAssociatedLogicalS1ConnectionItem,

	) UEAssociatedLogicalS1ConnectionItemResIEValue

	get func(*UEAssociatedLogicalS1ConnectionItemResIEValue,

	) (*UEAssociatedLogicalS1ConnectionItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) Codec() UEAssociatedLogicalS1ConnectionItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) New(value UEAssociatedLogicalS1ConnectionItem,

) (UEAssociatedLogicalS1ConnectionItemResIEField, error) {
	if b.inject == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) Get(field *UEAssociatedLogicalS1ConnectionItemResIEField) (*UEAssociatedLogicalS1ConnectionItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEAssociatedLogicalS1ConnectionItemValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItem].
type UEAssociatedLogicalS1ConnectionItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem,

		error)
	encode func(UEAssociatedLogicalS1ConnectionItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItem, aper.DecodeState,

	) (UEAssociatedLogicalS1ConnectionItem, aper.Snapshot,

	)
	compare func(UEAssociatedLogicalS1ConnectionItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemValueCodec) New(value UEAssociatedLogicalS1ConnectionItem,

) (UEAssociatedLogicalS1ConnectionItemAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResIEField is the concrete ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEAssociatedLogicalS1ConnectionItemResIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEField) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEAssociatedLogicalS1ConnectionItemResIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEAssociatedLogicalS1ConnectionItemResIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEAssociatedLogicalS1ConnectionItemResIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEAssociatedLogicalS1ConnectionItemResIEField{}
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
	var zero UEAssociatedLogicalS1ConnectionItemResIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding is the concrete IEBinding[UEAssociatedLogicalS1ConnectionItem, UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding struct {
	info   s00.FieldInfo
	codec  UEAssociatedLogicalS1ConnectionItemValueCodec
	inject func(UEAssociatedLogicalS1ConnectionItem,

	) UEAssociatedLogicalS1ConnectionItemResAckIEValue

	get func(*UEAssociatedLogicalS1ConnectionItemResAckIEValue,

	) (*UEAssociatedLogicalS1ConnectionItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) Codec() UEAssociatedLogicalS1ConnectionItemValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) New(value UEAssociatedLogicalS1ConnectionItem,

) (UEAssociatedLogicalS1ConnectionItemResAckIEField, error) {
	if b.inject == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) Get(field *UEAssociatedLogicalS1ConnectionItemResAckIEField) (*UEAssociatedLogicalS1ConnectionItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEField is the concrete ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEField) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEAssociatedLogicalS1ConnectionItemResAckIEField{}
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
	var zero UEAssociatedLogicalS1ConnectionItemResAckIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// HandoverNotifyValueCodec is the concrete ValueCodec[HandoverNotify].
type HandoverNotifyValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotify,

		error)
	encode func(HandoverNotify,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotify, aper.DecodeState,

	) (HandoverNotify, aper.Snapshot,

	)
	compare func(HandoverNotify, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyValueCodec) New(value HandoverNotify,

) (HandoverNotifyAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyValueCodec) EncodeAPER(value HandoverNotifyAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyValueCodec) encodeBudgetValue(value HandoverNotify,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyValueCodec) encodeChanged(value HandoverNotify,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageValueCodec is the concrete ValueCodec[InitialUEMessage].
type InitialUEMessageValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessage,

		error)
	encode func(InitialUEMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessage, aper.DecodeState,

	) (InitialUEMessage, aper.Snapshot,

	)
	compare func(InitialUEMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageValueCodec) New(value InitialUEMessage,

) (InitialUEMessageAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageValueCodec) EncodeAPER(value InitialUEMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageValueCodec) encodeBudgetValue(value InitialUEMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageValueCodec) encodeChanged(value InitialUEMessage,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionListResValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionListRes].
type UEAssociatedLogicalS1ConnectionListResValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListRes,

		error)
	encode func(UEAssociatedLogicalS1ConnectionListRes,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionListRes, aper.DecodeState,

	) (UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot,

	)
	compare func(UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionListResValueCodec) New(value UEAssociatedLogicalS1ConnectionListRes,

) (UEAssociatedLogicalS1ConnectionListResAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionListResAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionListResAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionListResAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionListResAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionListResValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionListResAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionListResAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionListResAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionListResAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionListResValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionListResAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionListResValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionListRes,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionListResValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionListRes,

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
func BridgeHandoverNotifyIEValueValidateS1APIEContainer(fields HandoverNotifyIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeInitialUEMessageIEValueValidateS1APIEContainer(fields InitialUEMessageIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeTunnelInformationExtIEsValueValidateS1APExtensionContainer(fields s11.TunnelInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.TunnelInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.TunnelInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTunnelInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields s12.UEAggregateMaximumBitratesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UEAggregateMaximumBitratesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UEAggregateMaximumBitratesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APExtensionContainer(fields s12.UEAppLayerMeasConfigExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UEAppLayerMeasConfigExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UEAppLayerMeasConfigExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APExtensionContainer(fields s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UEAssociatedLogicalS1ConnectionItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UEAssociatedLogicalS1ConnectionItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// UEAssociatedLogicalS1ConnectionItemResIEContainer is the concrete ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEContainer []UEAssociatedLogicalS1ConnectionItemResIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueValidateS1APIEContainer(fields UEAssociatedLogicalS1ConnectionItemResAckIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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

// UEAssociatedLogicalS1ConnectionItemResAckIEContainer is the concrete ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEContainer []UEAssociatedLogicalS1ConnectionItemResAckIEField

func HandoverNotifyIEValueERABIEContainerListCodec(table s00.HandoverNotifyIEValueIETable) HandoverNotifyIEValueERABIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverNotifyIEValueERABIEContainerListValueCodec{}
	}
	return HandoverNotifyIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverNotifyIEValueERABIEContainerList(value), err
	}, encode: func(value HandoverNotifyIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverNotifyIEContainer(value), fresh, budget)
	}, capture: func(v HandoverNotifyIEValueERABIEContainerList, options aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverNotifyIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func InitialUEMessageIEValueERABIEContainerListCodec(table s00.InitialUEMessageIEValueIETable) InitialUEMessageIEValueERABIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return InitialUEMessageIEValueERABIEContainerListValueCodec{}
	}
	return InitialUEMessageIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return InitialUEMessageIEValueERABIEContainerList(value), err
	}, encode: func(value InitialUEMessageIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialUEMessageIEContainer(value), fresh, budget)
	}, capture: func(v InitialUEMessageIEValueERABIEContainerList, options aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v InitialUEMessageIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable) UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec{}
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList(value), err
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResAckIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func UEAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec(table s00.UEAggregateMaximumBitratesExtIEsValueExtensionTable) s12.UEAggregateMaximumBitratesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUEAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
	}
	return func() s12.UEAggregateMaximumBitratesExtIEsExtFieldValueCodec {
		sealed := s12.UEAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAggregateMaximumBitratesExtIEsExtField, error) {
			var field s12.UEAggregateMaximumBitratesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UEAggregateMaximumBitratesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UEAggregateMaximumBitratesExtIEsExtField, options aper.DecodeState) (s12.UEAggregateMaximumBitratesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAggregateMaximumBitratesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEAppLayerMeasConfigExtIEsValueExtensionFieldTableCodec(table s00.UEAppLayerMeasConfigExtIEsValueExtensionTable) s12.UEAppLayerMeasConfigExtIEsExtFieldValueCodec {
	if !*s00.BridgeUEAppLayerMeasConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAppLayerMeasConfigExtIEsExtFieldValueCodec{}
	}
	return func() s12.UEAppLayerMeasConfigExtIEsExtFieldValueCodec {
		sealed := s12.UEAppLayerMeasConfigExtIEsExtFieldValueCodec{}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAppLayerMeasConfigExtIEsExtField, error) {
			var field s12.UEAppLayerMeasConfigExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UEAppLayerMeasConfigExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UEAppLayerMeasConfigExtIEsExtField, options aper.DecodeState) (s12.UEAppLayerMeasConfigExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAppLayerMeasConfigExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionFieldTableCodec(table s00.UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTable) s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodec{}
	}
	return func() s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodec {
		sealed := s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodec{}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, error) {
			var field s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, options aper.DecodeState) (s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TunnelInformationExtIEsValueExtensionTableCodec(table s00.TunnelInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TunnelInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeTunnelInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TunnelInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TunnelInformationExtIEsExtContainerValueCodec {
		sealed := s11.TunnelInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TunnelInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TunnelInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TunnelInformationExtIEsExtField
					if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s11.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TunnelInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TunnelInformationExtIEsExtContainer, options aper.DecodeState) (s11.TunnelInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s34.BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TunnelInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s34.BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEAggregateMaximumBitratesExtIEsValueExtensionTableCodec(table s00.UEAggregateMaximumBitratesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UEAggregateMaximumBitratesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUEAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UEAggregateMaximumBitratesExtIEsExtContainerValueCodec {
		sealed := s12.UEAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAggregateMaximumBitratesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UEAggregateMaximumBitratesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UEAggregateMaximumBitratesExtIEsExtField
					if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UEAggregateMaximumBitratesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UEAggregateMaximumBitratesExtIEsExtContainer, options aper.DecodeState) (s12.UEAggregateMaximumBitratesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UEAggregateMaximumBitratesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEAppLayerMeasConfigExtIEsValueExtensionTableCodec(table s00.UEAppLayerMeasConfigExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UEAppLayerMeasConfigExtIEsExtContainerValueCodec {
	if !*s00.BridgeUEAppLayerMeasConfigExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAppLayerMeasConfigExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UEAppLayerMeasConfigExtIEsExtContainerValueCodec {
		sealed := s12.UEAppLayerMeasConfigExtIEsExtContainerValueCodec{}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAppLayerMeasConfigExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UEAppLayerMeasConfigExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UEAppLayerMeasConfigExtIEsExtField
					if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UEAppLayerMeasConfigExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UEAppLayerMeasConfigExtIEsExtContainer, options aper.DecodeState) (s12.UEAppLayerMeasConfigExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UEAppLayerMeasConfigExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableCodec(table s00.UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodec {
		sealed := s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodec{}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField
					if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
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
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, options aper.DecodeState) (s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func HandoverNotifyIEValueIEFieldTableCodec(table s00.HandoverNotifyIEValueIETable) HandoverNotifyIEFieldValueCodec {
	if !*s00.BridgeHandoverNotifyIEValueIETableFieldBound(&table) {
		return HandoverNotifyIEFieldValueCodec{}
	}
	return HandoverNotifyIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverNotifyIEField, error) {
		var field HandoverNotifyIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field HandoverNotifyIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v HandoverNotifyIEField, options aper.DecodeState) (HandoverNotifyIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v HandoverNotifyIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(&v, &s)
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
func InitialUEMessageIEValueIEFieldTableCodec(table s00.InitialUEMessageIEValueIETable) InitialUEMessageIEFieldValueCodec {
	if !*s00.BridgeInitialUEMessageIEValueIETableFieldBound(&table) {
		return InitialUEMessageIEFieldValueCodec{}
	}
	return InitialUEMessageIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialUEMessageIEField, error) {
		var field InitialUEMessageIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field InitialUEMessageIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v InitialUEMessageIEField, options aper.DecodeState) (InitialUEMessageIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v InitialUEMessageIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(&v, &s)
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
func UEAssociatedLogicalS1ConnectionItemResAckIEValueIEFieldTableCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable) UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueIETableFieldBound(&table) {
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec{}
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, error) {
		var field UEAssociatedLogicalS1ConnectionItemResAckIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field UEAssociatedLogicalS1ConnectionItemResAckIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEField, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEField(&v, &s)
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
func UEAssociatedLogicalS1ConnectionItemResIEValueIEFieldTableCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable) UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueIETableFieldBound(&table) {
		return UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec{}
	}
	return UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, error) {
		var field UEAssociatedLogicalS1ConnectionItemResIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field UEAssociatedLogicalS1ConnectionItemResIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResIEField, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEField(&v, &s)
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
func HandoverNotifyIEValueIETableCodec(table s00.HandoverNotifyIEValueIETable, bounds aper.ListBounds) HandoverNotifyIEContainerValueCodec {
	if !*s00.BridgeHandoverNotifyIEValueIETableFieldBound(&table) {
		return HandoverNotifyIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverNotifyIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverNotifyIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverNotifyIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverNotifyIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
					return err
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
			return nil, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields HandoverNotifyIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v HandoverNotifyIEContainer, options aper.DecodeState) (HandoverNotifyIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v HandoverNotifyIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func InitialUEMessageIEValueIETableCodec(table s00.InitialUEMessageIEValueIETable, bounds aper.ListBounds) InitialUEMessageIEContainerValueCodec {
	if !*s00.BridgeInitialUEMessageIEValueIETableFieldBound(&table) {
		return InitialUEMessageIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return InitialUEMessageIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialUEMessageIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields InitialUEMessageIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field InitialUEMessageIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
					return err
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
			return nil, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields InitialUEMessageIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v InitialUEMessageIEContainer, options aper.DecodeState) (InitialUEMessageIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v InitialUEMessageIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable, bounds aper.ListBounds) UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueIETableFieldBound(&table) {
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResAckIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResAckIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
					return err
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
			return nil, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields UEAssociatedLogicalS1ConnectionItemResAckIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEContainer, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable, bounds aper.ListBounds) UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec {
	if !*s00.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueIETableFieldBound(&table) {
		return UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
					return err
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
			return nil, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields UEAssociatedLogicalS1ConnectionItemResIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEAssociatedLogicalS1ConnectionItemResIEContainer, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func HandoverNotifyIEValueProtocolErrorIEContainerListCodec(table s00.HandoverNotifyIEValueIETable) HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverNotifyIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value HandoverNotifyIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverNotifyIEContainer(value), fresh, budget)
	}, capture: func(v HandoverNotifyIEValueProtocolErrorIEContainerList, options aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverNotifyIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeHandoverNotifyIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func InitialUEMessageIEValueProtocolErrorIEContainerListCodec(table s00.InitialUEMessageIEValueIETable) InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return InitialUEMessageIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value InitialUEMessageIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialUEMessageIEContainer(value), fresh, budget)
	}, capture: func(v InitialUEMessageIEValueProtocolErrorIEContainerList, options aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v InitialUEMessageIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeInitialUEMessageIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable) UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResAckIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func HandoverNotifyIEValueProtocolIEContainerListCodec(table s00.HandoverNotifyIEValueIETable, bounds aper.ListBounds) HandoverNotifyIEValueProtocolIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return HandoverNotifyIEValueProtocolIEContainerListValueCodec{}
	}
	return HandoverNotifyIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverNotifyIEValueProtocolIEContainerList(value), err
	}, encode: func(value HandoverNotifyIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverNotifyIEContainer(value), fresh, budget)
	}, capture: func(v HandoverNotifyIEValueProtocolIEContainerList, options aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v HandoverNotifyIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func InitialUEMessageIEValueProtocolIEContainerListCodec(table s00.InitialUEMessageIEValueIETable, bounds aper.ListBounds) InitialUEMessageIEValueProtocolIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return InitialUEMessageIEValueProtocolIEContainerListValueCodec{}
	}
	return InitialUEMessageIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return InitialUEMessageIEValueProtocolIEContainerList(value), err
	}, encode: func(value InitialUEMessageIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialUEMessageIEContainer(value), fresh, budget)
	}, capture: func(v InitialUEMessageIEValueProtocolIEContainerList, options aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v InitialUEMessageIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable, bounds aper.ListBounds) UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec{}
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList(value), err
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResAckIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// handoverNotifyIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverNotifyIEValue].
type HandoverNotifyIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) HandoverNotifyIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (HandoverNotifyIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(v *HandoverNotifyIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(v *HandoverNotifyIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// initialUEMessageIEValueProtocolOpenValue is the concrete protocolOpenValue[InitialUEMessageIEValue].
type InitialUEMessageIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) InitialUEMessageIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (InitialUEMessageIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(v *InitialUEMessageIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(v *InitialUEMessageIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// tunnelInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TunnelInformationExtIEsValue].
type TunnelInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TunnelInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TunnelInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uEAggregateMaximumBitratesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UEAggregateMaximumBitratesExtIEsValue].
type UEAggregateMaximumBitratesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UEAggregateMaximumBitratesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UEAggregateMaximumBitratesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UEAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUEAggregateMaximumBitratesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(v *s12.UEAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUEAggregateMaximumBitratesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}

// uEAppLayerMeasConfigExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UEAppLayerMeasConfigExtIEsValue].
type UEAppLayerMeasConfigExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.UEAppLayerMeasConfigExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.UEAppLayerMeasConfigExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UEAppLayerMeasConfigExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeUEAppLayerMeasConfigExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionField(v *s12.UEAppLayerMeasConfigExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeUEAppLayerMeasConfigExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldFieldWithoutReplay(v))
}

// uEAssociatedLogicalS1ConnectionItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UEAssociatedLogicalS1ConnectionItemExtIEsValue].
type UEAssociatedLogicalS1ConnectionItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UEAssociatedLogicalS1ConnectionItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionField(v *s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldFieldReplay(v), *s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEField(v *UEAssociatedLogicalS1ConnectionItemResIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEField(v *UEAssociatedLogicalS1ConnectionItemResIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolOpenValue is the concrete protocolOpenValue[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResAckIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResAckIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEField(v *UEAssociatedLogicalS1ConnectionItemResAckIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEField(v *UEAssociatedLogicalS1ConnectionItemResAckIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// UEAppLayerMeasConfigAPERValue is the concrete APERValue[UEAppLayerMeasConfig].
type UEAppLayerMeasConfigAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEAppLayerMeasConfig

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAppLayerMeasConfigAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAppLayerMeasConfigAPERValue) WithoutReplay() UEAppLayerMeasConfigAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TunnelInformationAPERValue is the concrete APERValue[TunnelInformation].
type TunnelInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s34.TunnelInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TunnelInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TunnelInformationAPERValue) WithoutReplay() TunnelInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAggregateMaximumBitrateAPERValue is the concrete APERValue[UEAggregateMaximumBitrate].
type UEAggregateMaximumBitrateAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEAggregateMaximumBitrate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAggregateMaximumBitrateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAggregateMaximumBitrateAPERValue) WithoutReplay() UEAggregateMaximumBitrateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionListResAckAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionListResAck].
type UEAssociatedLogicalS1ConnectionListResAckAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEAssociatedLogicalS1ConnectionListResAck

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionListResAckAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionListResAckAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionListResAckAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItem].
type UEAssociatedLogicalS1ConnectionItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEAssociatedLogicalS1ConnectionItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyAPERValue is the concrete APERValue[HandoverNotify].
type HandoverNotifyAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverNotify

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyAPERValue) WithoutReplay() HandoverNotifyAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageAPERValue is the concrete APERValue[InitialUEMessage].
type InitialUEMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   InitialUEMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageAPERValue) WithoutReplay() InitialUEMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionListResAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionListRes].
type UEAssociatedLogicalS1ConnectionListResAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEAssociatedLogicalS1ConnectionListRes

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionListResAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionListResAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionListResAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTunnelInformationExtIEsValueValidateS1APIEContainer(fields s12.TunnelInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTunnelInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTunnelInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTunnelInformationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(fields s12.UEAggregateMaximumBitratesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUEAggregateMaximumBitratesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUEAggregateMaximumBitratesExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUEAggregateMaximumBitratesExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APIEContainer(fields s12.UEAppLayerMeasConfigExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeUEAppLayerMeasConfigExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeUEAppLayerMeasConfigExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeUEAppLayerMeasConfigExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APIEContainer(fields s12.UEAssociatedLogicalS1ConnectionItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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

// HandoverNotifyIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, error)
	encode  func(HandoverNotifyIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotifyIEValueERABIEContainerList, aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverNotifyIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyIEValueERABIEContainerListValueCodec) New(value HandoverNotifyIEValueERABIEContainerList) (HandoverNotifyIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverNotifyIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverNotifyIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverNotifyIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverNotifyIEValue].
type HandoverNotifyIEValueERABIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverNotifyIEValueCaptureS1APERABIEContainerList(v *HandoverNotifyIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APERABIEContainerList(v *HandoverNotifyIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverNotifyIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialUEMessageIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, error)
	encode  func(InitialUEMessageIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessageIEValueERABIEContainerList, aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, aper.Snapshot)
	compare func(InitialUEMessageIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageIEValueERABIEContainerListValueCodec) New(value InitialUEMessageIEValueERABIEContainerList) (InitialUEMessageIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageIEValueERABIEContainerListValueCodec) EncodeAPER(value InitialUEMessageIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageIEValueERABIEContainerListValueCodec) encodeBudgetValue(value InitialUEMessageIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageIEValueERABIEContainerListValueCodec) encodeChanged(value InitialUEMessageIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageIEValueERABIEContainerList is the concrete ERABIEContainerList[InitialUEMessageIEValue].
type InitialUEMessageIEValueERABIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeInitialUEMessageIEValueCaptureS1APERABIEContainerList(v *InitialUEMessageIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APERABIEContainerList(v *InitialUEMessageIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeInitialUEMessageIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList is the concrete ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList []UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APERABIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APERABIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList is the concrete ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList []UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APERABIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// HandoverNotifyIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverNotifyIEValue]].
type HandoverNotifyIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotifyIEField, error)
	encode  func(HandoverNotifyIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotifyIEField, aper.DecodeState) (HandoverNotifyIEField, aper.Snapshot)
	compare func(HandoverNotifyIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyIEFieldValueCodec) New(value HandoverNotifyIEField) (HandoverNotifyIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyIEFieldValueCodec) EncodeAPER(value HandoverNotifyIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyIEFieldValueCodec) encodeBudgetValue(value HandoverNotifyIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyIEFieldValueCodec) encodeChanged(value HandoverNotifyIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[InitialUEMessageIEValue]].
type InitialUEMessageIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessageIEField, error)
	encode  func(InitialUEMessageIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessageIEField, aper.DecodeState) (InitialUEMessageIEField, aper.Snapshot)
	compare func(InitialUEMessageIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageIEFieldValueCodec) New(value InitialUEMessageIEField) (InitialUEMessageIEFieldAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageIEFieldValueCodec) EncodeAPER(value InitialUEMessageIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageIEFieldValueCodec) encodeBudgetValue(value InitialUEMessageIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageIEFieldValueCodec) encodeChanged(value InitialUEMessageIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResAckIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResAckIEField) (UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResAckIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResAckIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResIEField, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResIEField) (UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverNotifyIEValue]].
type HandoverNotifyIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotifyIEContainer, error)
	encode  func(HandoverNotifyIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotifyIEContainer, aper.DecodeState) (HandoverNotifyIEContainer, aper.Snapshot)
	compare func(HandoverNotifyIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyIEContainerValueCodec) New(value HandoverNotifyIEContainer) (HandoverNotifyIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyIEContainerValueCodec) EncodeAPER(value HandoverNotifyIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyIEContainerValueCodec) encodeBudgetValue(value HandoverNotifyIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyIEContainerValueCodec) encodeChanged(value HandoverNotifyIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[InitialUEMessageIEValue]].
type InitialUEMessageIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessageIEContainer, error)
	encode  func(InitialUEMessageIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessageIEContainer, aper.DecodeState) (InitialUEMessageIEContainer, aper.Snapshot)
	compare func(InitialUEMessageIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageIEContainerValueCodec) New(value InitialUEMessageIEContainer) (InitialUEMessageIEContainerAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageIEContainerValueCodec) EncodeAPER(value InitialUEMessageIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageIEContainerValueCodec) encodeBudgetValue(value InitialUEMessageIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageIEContainerValueCodec) encodeChanged(value InitialUEMessageIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResAckIEContainer) (UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResAckIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResAckIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEContainer(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainer(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResIEContainer) (UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEContainer(v *UEAssociatedLogicalS1ConnectionItemResIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainer(v *UEAssociatedLogicalS1ConnectionItemResIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverNotifyIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotifyIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverNotifyIEValueProtocolErrorIEContainerList) (HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverNotifyIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverNotifyIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverNotifyIEValue].
type HandoverNotifyIEValueProtocolErrorIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverNotifyIEValueCaptureS1APProtocolErrorIEContainerList(v *HandoverNotifyIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolErrorIEContainerList(v *HandoverNotifyIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverNotifyIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, error)
	encode  func(InitialUEMessageIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessageIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) New(value InitialUEMessageIEValueProtocolErrorIEContainerList) (InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value InitialUEMessageIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value InitialUEMessageIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[InitialUEMessageIEValue].
type InitialUEMessageIEValueProtocolErrorIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeInitialUEMessageIEValueCaptureS1APProtocolErrorIEContainerList(v *InitialUEMessageIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolErrorIEContainerList(v *InitialUEMessageIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeInitialUEMessageIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList []UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolErrorIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolErrorIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList []UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolErrorIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// HandoverNotifyIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, error)
	encode  func(HandoverNotifyIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverNotifyIEValueProtocolIEContainerList, aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverNotifyIEValueProtocolIEContainerListValueCodec) New(value HandoverNotifyIEValueProtocolIEContainerList) (HandoverNotifyIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverNotifyIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverNotifyIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverNotifyIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverNotifyIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverNotifyIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverNotifyIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverNotifyIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverNotifyIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverNotifyIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverNotifyIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverNotifyIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverNotifyIEValue].
type HandoverNotifyIEValueProtocolIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainerList(v *HandoverNotifyIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainerList(v *HandoverNotifyIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverNotifyIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialUEMessageIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, error)
	encode  func(InitialUEMessageIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialUEMessageIEValueProtocolIEContainerList, aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialUEMessageIEValueProtocolIEContainerListValueCodec) New(value InitialUEMessageIEValueProtocolIEContainerList) (InitialUEMessageIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialUEMessageIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialUEMessageIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialUEMessageIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialUEMessageIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialUEMessageIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialUEMessageIEValueProtocolIEContainerListValueCodec) EncodeAPER(value InitialUEMessageIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitialUEMessageIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value InitialUEMessageIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialUEMessageIEValueProtocolIEContainerListValueCodec) encodeChanged(value InitialUEMessageIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialUEMessageIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[InitialUEMessageIEValue].
type InitialUEMessageIEValueProtocolIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainerList(v *InitialUEMessageIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainerList(v *InitialUEMessageIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeInitialUEMessageIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList []UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, error)
	encode  func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) New(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList []UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer

func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}

// HandoverNotifyIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverNotifyIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverNotifyIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverNotifyIEValue].
type HandoverNotifyIEValueProtocolIESingleContainer = HandoverNotifyIEField

func BridgeHandoverNotifyIEValueCaptureS1APProtocolIESingleContainer(v *HandoverNotifyIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIESingleContainer(v *HandoverNotifyIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// InitialUEMessageIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialUEMessageIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEValueERABIEContainerListAPERValue) WithoutReplay() InitialUEMessageIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[InitialUEMessageIEValue].
type InitialUEMessageIEValueProtocolIESingleContainer = InitialUEMessageIEField

func BridgeInitialUEMessageIEValueCaptureS1APProtocolIESingleContainer(v *InitialUEMessageIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIESingleContainer(v *InitialUEMessageIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverNotifyIEValue]].
type HandoverNotifyIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverNotifyIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEFieldAPERValue) WithoutReplay() HandoverNotifyIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageIEFieldAPERValue is the concrete APERValue[ProtocolIEField[InitialUEMessageIEValue]].
type InitialUEMessageIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialUEMessageIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEFieldAPERValue) WithoutReplay() InitialUEMessageIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverNotifyIEValue]].
type HandoverNotifyIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverNotifyIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEContainerAPERValue) WithoutReplay() HandoverNotifyIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[InitialUEMessageIEValue]].
type InitialUEMessageIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialUEMessageIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEContainerAPERValue) WithoutReplay() InitialUEMessageIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverNotifyIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialUEMessageIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverNotifyIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverNotifyIEValue]].
type HandoverNotifyIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverNotifyIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverNotifyIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverNotifyIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverNotifyIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialUEMessageIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[InitialUEMessageIEValue]].
type InitialUEMessageIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialUEMessageIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialUEMessageIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialUEMessageIEValueProtocolIEContainerListAPERValue) WithoutReplay() InitialUEMessageIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResAckIEValue]].
type UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEAssociatedLogicalS1ConnectionItemResIEValue]].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APHandoverNotify(v *HandoverNotify, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverNotify(v *HandoverNotify, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverNotifyIEValue(v *HandoverNotifyIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s00.BridgeCaptureS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s20.BridgeCaptureS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(320):
			{
				f := s.Begin()
				s.Bool(v.rowNotifySourceeNB == nil)
				if v.rowNotifySourceeNB != nil {
					s00.BridgeCaptureS1APNotifySourceeNB(v.rowNotifySourceeNB, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverNotifyIEValue) captureSemantics(s aper.SemanticCapture) HandoverNotifyIEValue {
	BridgeCaptureS1APHandoverNotifyIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverNotifyIEValue(v *HandoverNotifyIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s02.BridgeCompareS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(288):
			{
				f := s.Begin()
				s.Bool(v.rowPSCellInformation == nil)
				if v.rowPSCellInformation != nil {
					s20.BridgeCompareS1APPSCellInformation(v.rowPSCellInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(320):
			{
				f := s.Begin()
				s.Bool(v.rowNotifySourceeNB == nil)
				if v.rowNotifySourceeNB != nil {
					s02.BridgeCompareS1APNotifySourceeNB(v.rowNotifySourceeNB, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverNotifyIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverNotifyIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APInitialUEMessage(v *InitialUEMessage, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInitialUEMessage(v *InitialUEMessage, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInitialUEMessageIEValue(v *InitialUEMessageIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s00.BridgeCaptureS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(134):
			{
				f := s.Begin()
				s.Bool(v.rowRRCEstablishmentCause == nil)
				if v.rowRRCEstablishmentCause != nil {
					s00.BridgeCaptureS1APRRCEstablishmentCause(v.rowRRCEstablishmentCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(127):
			{
				f := s.Begin()
				s.Bool(v.rowCSGId == nil)
				if v.rowCSGId != nil {
					s00.BridgeCaptureS1APCSGId(v.rowCSGId, s)
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
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s00.BridgeCaptureS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(155):
			{
				f := s.Begin()
				s.Bool(v.rowGWTransportLayerAddress == nil)
				if v.rowGWTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowGWTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(160):
			{
				f := s.Begin()
				s.Bool(v.rowRelayNodeIndicator == nil)
				if v.rowRelayNodeIndicator != nil {
					s00.BridgeCaptureS1APRelayNodeIndicator(v.rowRelayNodeIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(170):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIType == nil)
				if v.rowGUMMEIType != nil {
					s00.BridgeCaptureS1APGUMMEIType(v.rowGUMMEIType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(184):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOLGWTransportLayerAddress == nil)
				if v.rowSIPTOLGWTransportLayerAddress != nil {
					s00.BridgeCaptureS1APTransportLayerAddress(v.rowSIPTOLGWTransportLayerAddress, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s00.BridgeCaptureS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(223):
			{
				f := s.Begin()
				s.Bool(v.rowMMEGroupID == nil)
				if v.rowMMEGroupID != nil {
					s00.BridgeCaptureS1APMMEGroupID(v.rowMMEGroupID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(230):
			{
				f := s.Begin()
				s.Bool(v.rowUEUsageType == nil)
				if v.rowUEUsageType != nil {
					s00.BridgeCaptureS1APUEUsageType(v.rowUEUsageType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(242):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBSupportIndicator == nil)
				if v.rowCEModeBSupportIndicator != nil {
					s00.BridgeCaptureS1APCEModeBSupportIndicator(v.rowCEModeBSupportIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(246):
			{
				f := s.Begin()
				s.Bool(v.rowDCNID == nil)
				if v.rowDCNID != nil {
					s00.BridgeCaptureS1APDCNID(v.rowDCNID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(250):
			{
				f := s.Begin()
				s.Bool(v.rowCoverageLevel == nil)
				if v.rowCoverageLevel != nil {
					s00.BridgeCaptureS1APCoverageLevel(v.rowCoverageLevel, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(263):
			{
				f := s.Begin()
				s.Bool(v.rowUEApplicationLayerMeasurementCapability == nil)
				if v.rowUEApplicationLayerMeasurementCapability != nil {
					s00.BridgeCaptureS1APUEApplicationLayerMeasurementCapability(v.rowUEApplicationLayerMeasurementCapability, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(281):
			{
				f := s.Begin()
				s.Bool(v.rowEDTSession == nil)
				if v.rowEDTSession != nil {
					s00.BridgeCaptureS1APEDTSession(v.rowEDTSession, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(302):
			{
				f := s.Begin()
				s.Bool(v.rowIABNodeIndication == nil)
				if v.rowIABNodeIndication != nil {
					s00.BridgeCaptureS1APIABNodeIndication(v.rowIABNodeIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(353):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocationRequested == nil)
				if v.rowCoarseUELocationRequested != nil {
					s00.BridgeCaptureS1APCoarseUELocationRequested(v.rowCoarseUELocationRequested, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialUEMessageIEValue) captureSemantics(s aper.SemanticCapture) InitialUEMessageIEValue {
	BridgeCaptureS1APInitialUEMessageIEValue(&v, &s)
	return v
}
func BridgeCompareS1APInitialUEMessageIEValue(v *InitialUEMessageIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s02.BridgeCompareS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s31.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s17.BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(134):
			{
				f := s.Begin()
				s.Bool(v.rowRRCEstablishmentCause == nil)
				if v.rowRRCEstablishmentCause != nil {
					s06.BridgeCompareS1APRRCEstablishmentCause(v.rowRRCEstablishmentCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s27.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(127):
			{
				f := s.Begin()
				s.Bool(v.rowCSGId == nil)
				if v.rowCSGId != nil {
					s02.BridgeCompareS1APCSGId(v.rowCSGId, s)
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
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s02.BridgeCompareS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(155):
			{
				f := s.Begin()
				s.Bool(v.rowGWTransportLayerAddress == nil)
				if v.rowGWTransportLayerAddress != nil {
					s07.BridgeCompareS1APTransportLayerAddress(v.rowGWTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(160):
			{
				f := s.Begin()
				s.Bool(v.rowRelayNodeIndicator == nil)
				if v.rowRelayNodeIndicator != nil {
					s06.BridgeCompareS1APRelayNodeIndicator(v.rowRelayNodeIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(170):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIType == nil)
				if v.rowGUMMEIType != nil {
					s02.BridgeCompareS1APGUMMEIType(v.rowGUMMEIType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s34.BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(184):
			{
				f := s.Begin()
				s.Bool(v.rowSIPTOLGWTransportLayerAddress == nil)
				if v.rowSIPTOLGWTransportLayerAddress != nil {
					s07.BridgeCompareS1APTransportLayerAddress(v.rowSIPTOLGWTransportLayerAddress, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(186):
			{
				f := s.Begin()
				s.Bool(v.rowLHNID == nil)
				if v.rowLHNID != nil {
					s02.BridgeCompareS1APLHNID(v.rowLHNID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(223):
			{
				f := s.Begin()
				s.Bool(v.rowMMEGroupID == nil)
				if v.rowMMEGroupID != nil {
					s02.BridgeCompareS1APMMEGroupID(v.rowMMEGroupID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(230):
			{
				f := s.Begin()
				s.Bool(v.rowUEUsageType == nil)
				if v.rowUEUsageType != nil {
					s07.BridgeCompareS1APUEUsageType(v.rowUEUsageType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(242):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBSupportIndicator == nil)
				if v.rowCEModeBSupportIndicator != nil {
					s02.BridgeCompareS1APCEModeBSupportIndicator(v.rowCEModeBSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(246):
			{
				f := s.Begin()
				s.Bool(v.rowDCNID == nil)
				if v.rowDCNID != nil {
					s02.BridgeCompareS1APDCNID(v.rowDCNID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(250):
			{
				f := s.Begin()
				s.Bool(v.rowCoverageLevel == nil)
				if v.rowCoverageLevel != nil {
					s02.BridgeCompareS1APCoverageLevel(v.rowCoverageLevel, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(263):
			{
				f := s.Begin()
				s.Bool(v.rowUEApplicationLayerMeasurementCapability == nil)
				if v.rowUEApplicationLayerMeasurementCapability != nil {
					s07.BridgeCompareS1APUEApplicationLayerMeasurementCapability(v.rowUEApplicationLayerMeasurementCapability, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(281):
			{
				f := s.Begin()
				s.Bool(v.rowEDTSession == nil)
				if v.rowEDTSession != nil {
					s02.BridgeCompareS1APEDTSession(v.rowEDTSession, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(302):
			{
				f := s.Begin()
				s.Bool(v.rowIABNodeIndication == nil)
				if v.rowIABNodeIndication != nil {
					s02.BridgeCompareS1APIABNodeIndication(v.rowIABNodeIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(339):
			{
				f := s.Begin()
				s.Bool(v.rowLTENTNTAIInformation == nil)
				if v.rowLTENTNTAIInformation != nil {
					s18.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(353):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocationRequested == nil)
				if v.rowCoarseUELocationRequested != nil {
					s02.BridgeCompareS1APCoarseUELocationRequested(v.rowCoarseUELocationRequested, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialUEMessageIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APInitialUEMessageIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APResetType(v *ResetType, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
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
	case s00.ResetTypeChoiceS1Interface:
		{
			f := s.Begin()
			s.Bool(v.S1Interface == nil)
			if v.S1Interface != nil {
				s00.BridgeCaptureS1APResetAll(v.S1Interface, s)
			}
			s.End(f, nil, false)
		}
	case s00.ResetTypeChoicePartOfS1Interface:
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(&v.PartOfS1Interface, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APResetType(v *ResetType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.ResetTypeChoiceS1Interface:
		{
			f := s.Begin()
			s.Bool(v.S1Interface == nil)
			if v.S1Interface != nil {
				s06.BridgeCompareS1APResetAll(v.S1Interface, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.ResetTypeChoicePartOfS1Interface:
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(&v.PartOfS1Interface, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAggregateMaximumBitrate(v *UEAggregateMaximumBitrate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.UEaggregateMaximumBitRateDL, s)
	s00.BridgeCaptureS1APBitRate(&v.UEaggregateMaximumBitRateUL, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUEAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAggregateMaximumBitrate(v *UEAggregateMaximumBitrate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.UEaggregateMaximumBitRateDL, s)
	s02.BridgeCompareS1APBitRate(&v.UEaggregateMaximumBitRateUL, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAppLayerMeasConfig(v *UEAppLayerMeasConfig, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.ContainerForAppLayerMeasConfig)
	s32.BridgeCaptureS1APAreaScopeOfQMC(&v.AreaScopeOfQMC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUEAppLayerMeasConfigExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAppLayerMeasConfig(v *UEAppLayerMeasConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes(v.ContainerForAppLayerMeasConfig)
	s32.BridgeCompareS1APAreaScopeOfQMC(&v.AreaScopeOfQMC, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(v *UEAssociatedLogicalS1ConnectionItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.MMEUES1APID == nil)
		if v.MMEUES1APID != nil {
			s00.BridgeCaptureS1APMMEUES1APID(v.MMEUES1APID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ENBUES1APID == nil)
		if v.ENBUES1APID != nil {
			s00.BridgeCaptureS1APENBUES1APID(v.ENBUES1APID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(v *UEAssociatedLogicalS1ConnectionItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.MMEUES1APID == nil)
		if v.MMEUES1APID != nil {
			s02.BridgeCompareS1APMMEUES1APID(v.MMEUES1APID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.ENBUES1APID == nil)
		if v.ENBUES1APID != nil {
			s02.BridgeCompareS1APENBUES1APID(v.ENBUES1APID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItemResAckIEValue(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(91):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionItem == nil)
				if v.rowUEAssociatedLogicalS1ConnectionItem != nil {
					BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(v.rowUEAssociatedLogicalS1ConnectionItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) captureSemantics(s aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResAckIEValue {
	BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItemResAckIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionItemResAckIEValue(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(91):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionItem == nil)
				if v.rowUEAssociatedLogicalS1ConnectionItem != nil {
					BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(v.rowUEAssociatedLogicalS1ConnectionItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEAssociatedLogicalS1ConnectionItemResAckIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItemResIEValue(v *UEAssociatedLogicalS1ConnectionItemResIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(91):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionItem == nil)
				if v.rowUEAssociatedLogicalS1ConnectionItem != nil {
					BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(v.rowUEAssociatedLogicalS1ConnectionItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAssociatedLogicalS1ConnectionItemResIEValue) captureSemantics(s aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResIEValue {
	BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItemResIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionItemResIEValue(v *UEAssociatedLogicalS1ConnectionItemResIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(91):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionItem == nil)
				if v.rowUEAssociatedLogicalS1ConnectionItem != nil {
					BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(v.rowUEAssociatedLogicalS1ConnectionItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEAssociatedLogicalS1ConnectionItemResIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEAssociatedLogicalS1ConnectionItemResIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(v *UEAssociatedLogicalS1ConnectionListRes, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(v *UEAssociatedLogicalS1ConnectionListRes, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(v *UEAssociatedLogicalS1ConnectionListResAck, s *aper.SemanticCapture) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(v *UEAssociatedLogicalS1ConnectionListResAck, s *aper.SemanticComparison) {
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
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAggregateMaximumBitrate represents the ASN.1 type UEAggregateMaximumBitrate (SEQUENCE).
type UEAggregateMaximumBitrate struct {
	replay                      aper.Snapshot
	stream                      aper.WireSpan
	received                    bool
	withoutReplay               bool
	receivedAbsolute            bool
	receivedBytes               aper.WireSpan
	receivedLocation            aper.Location
	UEaggregateMaximumBitRateDL s00.BitRate                                      `asn1:"tag:0,context,implicit"`
	UEaggregateMaximumBitRateUL s00.BitRate                                      `asn1:"tag:1,context,implicit"`
	IEExtensions                s12.UEAggregateMaximumBitratesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef           bool                                             `asn1:"-" json:"-"`
	extCount                    int64                                            `asn1:"-" json:"-"`
	extPresent                  []bool                                           `asn1:"-" json:"-"`
	extData                     [][]byte                                         `asn1:"-" json:"-"`
	perPadding                  aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding               []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin                   []aper.OpaqueOrigin
	extWire                     []aper.WireSpan
}

// UEAppLayerMeasConfig represents the ASN.1 type UEAppLayerMeasConfig (SEQUENCE).
type UEAppLayerMeasConfig struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	received                       bool
	withoutReplay                  bool
	receivedAbsolute               bool
	receivedBytes                  aper.WireSpan
	receivedLocation               aper.Location
	ContainerForAppLayerMeasConfig []byte                                     `asn1:"tag:0,context,implicit"`
	AreaScopeOfQMC                 s32.AreaScopeOfQMC                         `asn1:"tag:1,context,explicit"`
	IEExtensions                   s12.UEAppLayerMeasConfigExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                       `asn1:"-" json:"-"`
	extCount                       int64                                      `asn1:"-" json:"-"`
	extPresent                     []bool                                     `asn1:"-" json:"-"`
	extData                        [][]byte                                   `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}

// UEAssociatedLogicalS1ConnectionItem represents the ASN.1 type UE-associatedLogicalS1-ConnectionItem (SEQUENCE).
type UEAssociatedLogicalS1ConnectionItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MMEUES1APID       *s00.MMEUES1APID                                          `asn1:"tag:0,context,implicit,optional" json:"MMEUES1APID,omitempty"`
	ENBUES1APID       *s00.ENBUES1APID                                          `asn1:"tag:1,context,implicit,optional" json:"ENBUES1APID,omitempty"`
	IEExtensions      s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                                      `asn1:"-" json:"-"`
	extCount          int64                                                     `asn1:"-" json:"-"`
	extPresent        []bool                                                    `asn1:"-" json:"-"`
	extData           [][]byte                                                  `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes UEAggregateMaximumBitrate to APER format.
func (v *UEAggregateMaximumBitrate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEAggregateMaximumBitrate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.UEaggregateMaximumBitRateDL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uEaggregateMaximumBitRateDL: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.UEaggregateMaximumBitRateUL), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uEaggregateMaximumBitRateUL: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEAggregateMaximumBitrate from APER format.
func (v *UEAggregateMaximumBitrate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEAggregateMaximumBitrate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEAggregateMaximumBitrate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAggregateMaximumBitrate")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEAggregateMaximumBitrate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEAggregateMaximumBitrate{}
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
	val_ueaggregatemaximumbitratedl, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEaggregateMaximumBitRateDL")
	}
	v.UEaggregateMaximumBitRateDL = s00.BitRate(val_ueaggregatemaximumbitratedl)
	val_ueaggregatemaximumbitrateul, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEaggregateMaximumBitRateUL")
	}
	v.UEaggregateMaximumBitRateUL = s00.BitRate(val_ueaggregatemaximumbitrateul)
	if opt_ieextensions {
		tmp_ieextensions := make(s12.UEAggregateMaximumBitratesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAggregateMaximumBitratesExtIEsExtField
				if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes UEAppLayerMeasConfig to APER format.
func (v *UEAppLayerMeasConfig) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEAppLayerMeasConfig) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, v.ContainerForAppLayerMeasConfig, 1, 1000, true); err != nil {
		return fmt.Errorf("encoding containerForAppLayerMeasConfig: %w", err)
	}
	if err := s32.BridgeAreaScopeOfQMCMethodMarshalAPERTo(&v.AreaScopeOfQMC, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding areaScopeOfQMC: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEAppLayerMeasConfig from APER format.
func (v *UEAppLayerMeasConfig) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEAppLayerMeasConfig with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEAppLayerMeasConfig) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAppLayerMeasConfig")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEAppLayerMeasConfig")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAppLayerMeasConfig")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAppLayerMeasConfig")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEAppLayerMeasConfig) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEAppLayerMeasConfig{}
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
	val_containerforapplayermeasconfig, err := aper.DecodeOctetStringAligned(bb, 1, 1000, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ContainerForAppLayerMeasConfig")
	}
	v.ContainerForAppLayerMeasConfig = val_containerforapplayermeasconfig
	toleranceMark_areascopeofqmc := bb.EnterComponent("AreaScopeOfQMC")
	if err := s32.BridgeAreaScopeOfQMCMethodUnmarshalAPERFrom(&v.AreaScopeOfQMC, bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	bb.LeaveComponent(toleranceMark_areascopeofqmc)
	if opt_ieextensions {
		tmp_ieextensions := make(s12.UEAppLayerMeasConfigExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAppLayerMeasConfigExtIEsExtField
				if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// MarshalAPER encodes UEAssociatedLogicalS1ConnectionItem to APER format.
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.MMEUES1APID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ENBUES1APID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.MMEUES1APID != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
		}
	}
	if v.ENBUES1APID != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return fmt.Errorf("encoding eNB-UE-S1AP-ID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEAssociatedLogicalS1ConnectionItem from APER format.
func (v *UEAssociatedLogicalS1ConnectionItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEAssociatedLogicalS1ConnectionItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEAssociatedLogicalS1ConnectionItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEAssociatedLogicalS1ConnectionItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEAssociatedLogicalS1ConnectionItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_mmeues1apid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_enbues1apid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_mmeues1apid {
		val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MMEUES1APID")
		}
		tmp_mmeues1apid := s00.MMEUES1APID(val_mmeues1apid)
		if err := aper.ChargeValue(bb, tmp_mmeues1apid); err != nil {
			return err
		}
		v.MMEUES1APID = (*s00.MMEUES1APID)(bb.OwnInt64(int64(tmp_mmeues1apid)))

	}
	if opt_enbues1apid {
		val_enbues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ENBUES1APID")
		}
		tmp_enbues1apid := s00.ENBUES1APID(val_enbues1apid)
		if err := aper.ChargeValue(bb, tmp_enbues1apid); err != nil {
			return err
		}
		v.ENBUES1APID = (*s00.ENBUES1APID)(bb.OwnInt64(int64(tmp_enbues1apid)))

	}
	if opt_ieextensions {
		tmp_ieextensions := make(s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField
				if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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
func (v *UEAggregateMaximumBitrate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAggregateMaximumBitrate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAggregateMaximumBitrate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAggregateMaximumBitrate) WithoutReplay() UEAggregateMaximumBitrate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAggregateMaximumBitrate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAppLayerMeasConfig) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAppLayerMeasConfig", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAppLayerMeasConfig", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAppLayerMeasConfig) WithoutReplay() UEAppLayerMeasConfig {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAppLayerMeasConfig
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAssociatedLogicalS1ConnectionItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAssociatedLogicalS1ConnectionItem) WithoutReplay() UEAssociatedLogicalS1ConnectionItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAssociatedLogicalS1ConnectionItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UEAggregateMaximumBitrate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEAggregateMaximumBitrate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEAggregateMaximumBitrate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEAppLayerMeasConfig) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEAppLayerMeasConfig) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAppLayerMeasConfig.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAppLayerMeasConfig.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEAppLayerMeasConfig) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAppLayerMeasConfig.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAppLayerMeasConfig.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEAssociatedLogicalS1ConnectionItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEAssociatedLogicalS1ConnectionItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAssociatedLogicalS1ConnectionItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAssociatedLogicalS1ConnectionItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEAssociatedLogicalS1ConnectionItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEAssociatedLogicalS1ConnectionItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEAssociatedLogicalS1ConnectionItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEAggregateMaximumBitrate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAggregateMaximumBitrate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAggregateMaximumBitrate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAggregateMaximumBitrate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAggregateMaximumBitrate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAggregateMaximumBitrate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAggregateMaximumBitrate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAggregateMaximumBitrate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAggregateMaximumBitrate")
}
func (v *UEAggregateMaximumBitrate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAggregateMaximumBitrate")
}
func (v *UEAggregateMaximumBitrate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAggregateMaximumBitrate(v, &s)
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
func (v *UEAggregateMaximumBitrate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAggregateMaximumBitrate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEAppLayerMeasConfig) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAppLayerMeasConfig")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAppLayerMeasConfig) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAppLayerMeasConfig")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAppLayerMeasConfig(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAppLayerMeasConfig")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAppLayerMeasConfig")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAppLayerMeasConfig) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAppLayerMeasConfig")
}
func (v *UEAppLayerMeasConfig) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAppLayerMeasConfig")
}
func (v *UEAppLayerMeasConfig) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAppLayerMeasConfig(v, &s)
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
func (v *UEAppLayerMeasConfig) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAppLayerMeasConfig) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEAssociatedLogicalS1ConnectionItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAssociatedLogicalS1ConnectionItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionItem")
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionItem")
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(v, &s)
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
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAssociatedLogicalS1ConnectionItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEAggregateMaximumBitrate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAggregateMaximumBitrate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAggregateMaximumBitrate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAggregateMaximumBitrate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAggregateMaximumBitrate{}
		return report, aper.OperationError(err, "UEAggregateMaximumBitrate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAggregateMaximumBitrate")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAppLayerMeasConfig) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAppLayerMeasConfig")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAppLayerMeasConfig
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAppLayerMeasConfig(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAppLayerMeasConfig{}
		return report, aper.OperationError(err, "UEAppLayerMeasConfig")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAppLayerMeasConfig")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAssociatedLogicalS1ConnectionItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAssociatedLogicalS1ConnectionItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAssociatedLogicalS1ConnectionItem{}
		return report, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAssociatedLogicalS1ConnectionItem")
}

// HandoverNotify represents the ASN.1 type HandoverNotify (SEQUENCE).
type HandoverNotify struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      HandoverNotifyIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                      `asn1:"-" json:"-"`
	extCount         int64                     `asn1:"-" json:"-"`
	extPresent       []bool                    `asn1:"-" json:"-"`
	extData          [][]byte                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// InitialUEMessage represents the ASN.1 type InitialUEMessage (SEQUENCE).
type InitialUEMessage struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      InitialUEMessageIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ResetType represents the ASN.1 CHOICE type ResetType.
type ResetType struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding                   `json:"-"`
	perOpenTypePadding aper.CompletePadding                   `json:"-"`
	UnknownExtension   *aper.ChoiceExtension                  `json:"UnknownExtension,omitempty"`
	S1Interface        *s00.ResetAll                          `json:"S1Interface,omitempty"`
	PartOfS1Interface  UEAssociatedLogicalS1ConnectionListRes `json:"PartOfS1Interface,omitzero"`
}
type UEAssociatedLogicalS1ConnectionListRes = []UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
type UEAssociatedLogicalS1ConnectionListResAck = []UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer

// MarshalAPER encodes HandoverNotify to APER format.
func (v *HandoverNotify) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverNotify) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes HandoverNotify from APER format.
func (v *HandoverNotify) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverNotify with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverNotify) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverNotify")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverNotify")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverNotify")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverNotify")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverNotify) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverNotify{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(HandoverNotifyIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem HandoverNotifyIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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

// MarshalAPER encodes InitialUEMessage to APER format.
func (v *InitialUEMessage) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InitialUEMessage) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes InitialUEMessage from APER format.
func (v *InitialUEMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InitialUEMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InitialUEMessage) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InitialUEMessage")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialUEMessage")
	}
	padding, err := aper.CaptureFinalBits(bb, "InitialUEMessage")
	if err != nil {
		return runtime.WrapDecodePath(err, "InitialUEMessage")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InitialUEMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialUEMessage{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(InitialUEMessageIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem InitialUEMessageIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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

// MarshalAPER encodes ResetType to APER format.
func (v *ResetType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *ResetType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "ResetType:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "ResetType:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "ResetType:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "ResetType:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.ResetTypeChoiceS1Interface:
		if v.S1Interface == nil {
			return fmt.Errorf("choice alternative s1-Interface is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.S1Interface), 1, true); err != nil {
			return fmt.Errorf("encoding s1-Interface: %w", err)
		}
	case s00.ResetTypeChoicePartOfS1Interface:
		if err := aper.EncodeCollection(bb, int64(len(v.PartOfS1Interface)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_partofs1interface, fragmentLength_partofs1interface int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_partofs1interface < 0 || fragmentOffset_partofs1interface > int64(len(v.PartOfS1Interface)) || fragmentLength_partofs1interface < 0 || fragmentLength_partofs1interface > int64(len(v.PartOfS1Interface[fragmentOffset_partofs1interface:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.PartOfS1Interface[fragmentOffset_partofs1interface : fragmentOffset_partofs1interface+fragmentLength_partofs1interface] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding partOfS1-Interface element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding partOfS1-Interface: %w", err)
		}
	default:
		return fmt.Errorf("unknown ResetType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ResetType from APER format.
func (v *ResetType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResetType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResetType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResetType")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetType")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResetType")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResetType")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *ResetType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetType{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.ResetTypeChoiceS1Interface:
		val_s1interface, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "S1Interface"})
		if err != nil {
			return runtime.WrapDecodePath(err, "S1Interface")
		}
		tmp_s1interface := s00.ResetAll(val_s1interface)
		if err := aper.ChargeValue(bb, tmp_s1interface); err != nil {
			return err
		}
		v.S1Interface = (*s00.ResetAll)(bb.OwnInt64(int64(tmp_s1interface)))

	case s00.ResetTypeChoicePartOfS1Interface:
		tmp_partofs1interface := make(UEAssociatedLogicalS1ConnectionListRes, 0)
		_, errCollection_partofs1interface := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_partofs1interface, fragmentLength_partofs1interface int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_partofs1interface < 0 || fragmentLength_partofs1interface < 0 || fragmentLength_partofs1interface > int64(^uint(0)>>1) || fragmentOffset_partofs1interface > int64(^uint(0)>>1)-fragmentLength_partofs1interface {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_partofs1interface; i++ {
				var elem UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("PartOfS1Interface[%d]", fragmentOffset_partofs1interface+i))
				}
				if next, err := aper.AppendValues(bb, tmp_partofs1interface, elem); err != nil {
					return err
				} else {
					tmp_partofs1interface = next
				}
			}
			return nil
		})
		if errCollection_partofs1interface != nil {
			return runtime.WrapDecodePath(errCollection_partofs1interface, "PartOfS1Interface")
		}
		v.PartOfS1Interface = tmp_partofs1interface
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue struct {
	Value UEAssociatedLogicalS1ConnectionListRes
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResTo appends a UEAssociatedLogicalS1ConnectionListRes list to bb.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResTo(list UEAssociatedLogicalS1ConnectionListRes, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

type BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue struct {
	Value UEAssociatedLogicalS1ConnectionListResAck
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo appends a UEAssociatedLogicalS1ConnectionListResAck list to bb.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(list UEAssociatedLogicalS1ConnectionListResAck, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverNotify) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverNotify", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverNotify", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverNotify) WithoutReplay() HandoverNotify {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverNotify
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitialUEMessage) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitialUEMessage", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InitialUEMessage", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitialUEMessage) WithoutReplay() InitialUEMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InitialUEMessage
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResetType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResetType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ResetType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResetType) WithoutReplay() ResetType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ResetType
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverNotify) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverNotify) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverNotify.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverNotify.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverNotify) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverNotify.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverNotify.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *InitialUEMessage) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InitialUEMessage) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialUEMessage.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialUEMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InitialUEMessage) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialUEMessage.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialUEMessage.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverNotify) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverNotify")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverNotify) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverNotify")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverNotify(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverNotify")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverNotify")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverNotify) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverNotify")
}
func (v *HandoverNotify) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverNotify")
}
func (v *HandoverNotify) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverNotify(v, &s)
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
func (v *HandoverNotify) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverNotify) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InitialUEMessage) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InitialUEMessage")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InitialUEMessage) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InitialUEMessage")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInitialUEMessage(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InitialUEMessage")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InitialUEMessage")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InitialUEMessage) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InitialUEMessage")
}
func (v *InitialUEMessage) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InitialUEMessage")
}
func (v *InitialUEMessage) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInitialUEMessage(v, &s)
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
func (v *InitialUEMessage) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InitialUEMessage) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ResetType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ResetType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ResetType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResetType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APResetType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ResetType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ResetType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ResetType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ResetType")
}
func (v *ResetType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ResetType")
}
func (v *ResetType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APResetType(v, &s)
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
func (v *ResetType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ResetType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverNotify) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverNotify")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverNotify
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverNotify(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverNotify{}
		return report, aper.OperationError(err, "HandoverNotify")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverNotify")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InitialUEMessage) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InitialUEMessage")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InitialUEMessage
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInitialUEMessage(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InitialUEMessage{}
		return report, aper.OperationError(err, "InitialUEMessage")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InitialUEMessage")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ResetType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResetType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ResetType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APResetType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ResetType{}
		return report, aper.OperationError(err, "ResetType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResetType")
}

// NewResetTypeUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewResetTypeUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (ResetType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeUnknownExtension")
	}
	value := ResetType{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeUnknownExtension")
	}
	return value, aper.OperationError(nil, "ResetTypeUnknownExtension")
}

type HandoverNotifyIEValue struct {
	id                         s00.ProtocolIEID
	received                   aper.WireSpan
	replay                     aper.Snapshot
	opaque                     aper.OpaqueOpenType
	isOpaque                   bool
	rowMMEUES1APID             *s00.MMEUES1APID
	rowENBUES1APID             *s00.ENBUES1APID
	rowEUTRANCGI               *s17.EUTRANCGI
	rowTAI                     *s31.TAI
	rowTunnelInformationForBBF *s34.TunnelInformation
	rowLHNID                   *s00.LHNID
	rowPSCellInformation       *s20.PSCellInformation
	rowNotifySourceeNB         *s00.NotifySourceeNB
	rowLTENTNTAIInformation    *s18.LTENTNTAIInformation
}

func (v HandoverNotifyIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(176):
		return v.rowTunnelInformationForBBF != nil
	case s00.ProtocolIEID(186):
		return v.rowLHNID != nil
	case s00.ProtocolIEID(288):
		return v.rowPSCellInformation != nil
	case s00.ProtocolIEID(320):
		return v.rowNotifySourceeNB != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}
func (v *HandoverNotifyIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverNotifyIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs"}}
}
func (HandoverNotifyIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(176):
		return aper.UnknownSelector
	case s00.ProtocolIEID(186):
		return aper.UnknownSelector
	case s00.ProtocolIEID(288):
		return aper.UnknownSelector
	case s00.ProtocolIEID(320):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
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
	case s00.ProtocolIEID(66):
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
func (v *HandoverNotifyIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *HandoverNotifyIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *HandoverNotifyIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}
func (v *HandoverNotifyIEValue) AsTAI() (*s31.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}
func (v *HandoverNotifyIEValue) AsTunnelInformationForBBF() (*s34.TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}
func (v *HandoverNotifyIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}
func (v *HandoverNotifyIEValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}
func (v *HandoverNotifyIEValue) AsNotifySourceeNB() (*s00.NotifySourceeNB, bool) {
	if v == nil || v.id != s00.ProtocolIEID(320) || v.rowNotifySourceeNB == nil {
		return nil, false
	}
	return v.rowNotifySourceeNB, true
}
func (v *HandoverNotifyIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v HandoverNotifyIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverNotifyIEValue, error) {
	out := HandoverNotifyIEValue{id: id}
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
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.EUTRANCGI
		child := scope
		if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		*s17.BridgeEUTRANCGIFieldPerPadding(&value) = padding
		*s17.BridgeEUTRANCGIFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeEUTRANCGIFieldReceivedBytes(&value))
		*s17.BridgeEUTRANCGIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(67):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.TAI
		child := scope
		if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s31.BridgeTAIFieldPerPadding(&value) = padding
		*s31.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeTAIFieldReceivedBytes(&value))
		*s31.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(176):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s34.TunnelInformation
		child := scope
		if err := s34.BridgeTunnelInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		*s34.BridgeTunnelInformationFieldPerPadding(&value) = padding
		*s34.BridgeTunnelInformationFieldReceived(&value) = true
		raw.RetainContents(s34.BridgeTunnelInformationFieldReceivedBytes(&value))
		*s34.BridgeTunnelInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTunnelInformationForBBF = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(186):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.LHNID, error) {
			var v struct{ Value s00.LHNID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 32, 256, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.LHNID(val_value)
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
		out.rowLHNID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(288):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.PSCellInformation
		child := scope
		if err := s20.BridgePSCellInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PSCellInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PSCellInformation")
		if err != nil {
			return out, err
		}
		*s20.BridgePSCellInformationFieldPerPadding(&value) = padding
		*s20.BridgePSCellInformationFieldReceived(&value) = true
		raw.RetainContents(s20.BridgePSCellInformationFieldReceivedBytes(&value))
		*s20.BridgePSCellInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPSCellInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(320):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NotifySourceeNB"})
		value := s00.NotifySourceeNB(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NotifySourceeNB:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNotifySourceeNB = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(339):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.LTENTNTAIInformation
		child := scope
		if err := s18.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s18.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s18.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s18.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowLTENTNTAIInformation = &value
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
func (v HandoverNotifyIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverNotifyIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-EUTRAN-CGI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeEUTRANCGIMethodMarshalAPERBudget(v.rowEUTRANCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(67):
		if v.rowTAI == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(176):
		if v.rowTunnelInformationForBBF == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-Tunnel-Information-for-BBF:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s34.BridgeTunnelInformationMethodMarshalAPERBudget(v.rowTunnelInformationForBBF, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(186):
		if v.rowLHNID == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-LHN-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.LHNID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.LHNID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 32, 256, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLHNID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(288):
		if v.rowPSCellInformation == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-PSCellInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgePSCellInformationMethodMarshalAPERBudget(v.rowPSCellInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(320):
		if v.rowNotifySourceeNB == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-NotifySourceeNB:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNotifySourceeNB), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverNotifyIEs.id-LTE-NTN-TAI-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverNotifyIEValue:", v.id)
	}
}

type InitialUEMessageIEValue struct {
	id                                         s00.ProtocolIEID
	received                                   aper.WireSpan
	replay                                     aper.Snapshot
	opaque                                     aper.OpaqueOpenType
	isOpaque                                   bool
	rowENBUES1APID                             *s00.ENBUES1APID
	rowNASPDU                                  *s00.NASPDU
	rowTAI                                     *s31.TAI
	rowEUTRANCGI                               *s17.EUTRANCGI
	rowRRCEstablishmentCause                   *s00.RRCEstablishmentCause
	rowSTMSI                                   *s27.STMSI
	rowCSGId                                   *s00.CSGId
	rowGUMMEIID                                *s18.GUMMEI
	rowCellAccessMode                          *s00.CellAccessMode
	rowGWTransportLayerAddress                 *s00.TransportLayerAddress
	rowRelayNodeIndicator                      *s00.RelayNodeIndicator
	rowGUMMEIType                              *s00.GUMMEIType
	rowTunnelInformationForBBF                 *s34.TunnelInformation
	rowSIPTOLGWTransportLayerAddress           *s00.TransportLayerAddress
	rowLHNID                                   *s00.LHNID
	rowMMEGroupID                              *s00.MMEGroupID
	rowUEUsageType                             *s00.UEUsageType
	rowCEModeBSupportIndicator                 *s00.CEModeBSupportIndicator
	rowDCNID                                   *s00.DCNID
	rowCoverageLevel                           *s00.CoverageLevel
	rowUEApplicationLayerMeasurementCapability *s00.UEApplicationLayerMeasurementCapability
	rowEDTSession                              *s00.EDTSession
	rowIABNodeIndication                       *s00.IABNodeIndication
	rowLTENTNTAIInformation                    *s18.LTENTNTAIInformation
	rowCoarseUELocationRequested               *s00.CoarseUELocationRequested
}

func (v InitialUEMessageIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(26):
		return v.rowNASPDU != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(134):
		return v.rowRRCEstablishmentCause != nil
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(75):
		return v.rowGUMMEIID != nil
	case s00.ProtocolIEID(145):
		return v.rowCellAccessMode != nil
	case s00.ProtocolIEID(155):
		return v.rowGWTransportLayerAddress != nil
	case s00.ProtocolIEID(160):
		return v.rowRelayNodeIndicator != nil
	case s00.ProtocolIEID(170):
		return v.rowGUMMEIType != nil
	case s00.ProtocolIEID(176):
		return v.rowTunnelInformationForBBF != nil
	case s00.ProtocolIEID(184):
		return v.rowSIPTOLGWTransportLayerAddress != nil
	case s00.ProtocolIEID(186):
		return v.rowLHNID != nil
	case s00.ProtocolIEID(223):
		return v.rowMMEGroupID != nil
	case s00.ProtocolIEID(230):
		return v.rowUEUsageType != nil
	case s00.ProtocolIEID(242):
		return v.rowCEModeBSupportIndicator != nil
	case s00.ProtocolIEID(246):
		return v.rowDCNID != nil
	case s00.ProtocolIEID(250):
		return v.rowCoverageLevel != nil
	case s00.ProtocolIEID(263):
		return v.rowUEApplicationLayerMeasurementCapability != nil
	case s00.ProtocolIEID(281):
		return v.rowEDTSession != nil
	case s00.ProtocolIEID(302):
		return v.rowIABNodeIndication != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	case s00.ProtocolIEID(353):
		return v.rowCoarseUELocationRequested != nil
	}
	return false
}
func (v *InitialUEMessageIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (InitialUEMessageIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs"}}
}
func (InitialUEMessageIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(26):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(134):
		return aper.UnknownSelector
	case s00.ProtocolIEID(96):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(75):
		return aper.UnknownSelector
	case s00.ProtocolIEID(145):
		return aper.UnknownSelector
	case s00.ProtocolIEID(155):
		return aper.UnknownSelector
	case s00.ProtocolIEID(160):
		return aper.UnknownSelector
	case s00.ProtocolIEID(170):
		return aper.UnknownSelector
	case s00.ProtocolIEID(176):
		return aper.UnknownSelector
	case s00.ProtocolIEID(184):
		return aper.UnknownSelector
	case s00.ProtocolIEID(186):
		return aper.UnknownSelector
	case s00.ProtocolIEID(223):
		return aper.UnknownSelector
	case s00.ProtocolIEID(230):
		return aper.UnknownSelector
	case s00.ProtocolIEID(242):
		return aper.UnknownSelector
	case s00.ProtocolIEID(246):
		return aper.UnknownSelector
	case s00.ProtocolIEID(250):
		return aper.UnknownSelector
	case s00.ProtocolIEID(263):
		return aper.UnknownSelector
	case s00.ProtocolIEID(281):
		return aper.UnknownSelector
	case s00.ProtocolIEID(302):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
		return aper.UnknownSelector
	case s00.ProtocolIEID(353):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
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
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
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
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
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
	case s00.ProtocolIEID(185):
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
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
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
func (v *InitialUEMessageIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *InitialUEMessageIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}
func (v *InitialUEMessageIEValue) AsTAI() (*s31.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}
func (v *InitialUEMessageIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}
func (v *InitialUEMessageIEValue) AsRRCEstablishmentCause() (*s00.RRCEstablishmentCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(134) || v.rowRRCEstablishmentCause == nil {
		return nil, false
	}
	return v.rowRRCEstablishmentCause, true
}
func (v *InitialUEMessageIEValue) AsSTMSI() (*s27.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}
func (v *InitialUEMessageIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}
func (v *InitialUEMessageIEValue) AsGUMMEIID() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(75) || v.rowGUMMEIID == nil {
		return nil, false
	}
	return v.rowGUMMEIID, true
}
func (v *InitialUEMessageIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}
func (v *InitialUEMessageIEValue) AsGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(155) || v.rowGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowGWTransportLayerAddress, true
}
func (v *InitialUEMessageIEValue) AsRelayNodeIndicator() (*s00.RelayNodeIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(160) || v.rowRelayNodeIndicator == nil {
		return nil, false
	}
	return v.rowRelayNodeIndicator, true
}
func (v *InitialUEMessageIEValue) AsGUMMEIType() (*s00.GUMMEIType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(170) || v.rowGUMMEIType == nil {
		return nil, false
	}
	return v.rowGUMMEIType, true
}
func (v *InitialUEMessageIEValue) AsTunnelInformationForBBF() (*s34.TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}
func (v *InitialUEMessageIEValue) AsSIPTOLGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(184) || v.rowSIPTOLGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSIPTOLGWTransportLayerAddress, true
}
func (v *InitialUEMessageIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}
func (v *InitialUEMessageIEValue) AsMMEGroupID() (*s00.MMEGroupID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(223) || v.rowMMEGroupID == nil {
		return nil, false
	}
	return v.rowMMEGroupID, true
}
func (v *InitialUEMessageIEValue) AsUEUsageType() (*s00.UEUsageType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(230) || v.rowUEUsageType == nil {
		return nil, false
	}
	return v.rowUEUsageType, true
}
func (v *InitialUEMessageIEValue) AsCEModeBSupportIndicator() (*s00.CEModeBSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(242) || v.rowCEModeBSupportIndicator == nil {
		return nil, false
	}
	return v.rowCEModeBSupportIndicator, true
}
func (v *InitialUEMessageIEValue) AsDCNID() (*s00.DCNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(246) || v.rowDCNID == nil {
		return nil, false
	}
	return v.rowDCNID, true
}
func (v *InitialUEMessageIEValue) AsCoverageLevel() (*s00.CoverageLevel, bool) {
	if v == nil || v.id != s00.ProtocolIEID(250) || v.rowCoverageLevel == nil {
		return nil, false
	}
	return v.rowCoverageLevel, true
}
func (v *InitialUEMessageIEValue) AsUEApplicationLayerMeasurementCapability() (*s00.UEApplicationLayerMeasurementCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(263) || v.rowUEApplicationLayerMeasurementCapability == nil {
		return nil, false
	}
	return v.rowUEApplicationLayerMeasurementCapability, true
}
func (v *InitialUEMessageIEValue) AsEDTSession() (*s00.EDTSession, bool) {
	if v == nil || v.id != s00.ProtocolIEID(281) || v.rowEDTSession == nil {
		return nil, false
	}
	return v.rowEDTSession, true
}
func (v *InitialUEMessageIEValue) AsIABNodeIndication() (*s00.IABNodeIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(302) || v.rowIABNodeIndication == nil {
		return nil, false
	}
	return v.rowIABNodeIndication, true
}
func (v *InitialUEMessageIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v *InitialUEMessageIEValue) AsCoarseUELocationRequested() (*s00.CoarseUELocationRequested, bool) {
	if v == nil || v.id != s00.ProtocolIEID(353) || v.rowCoarseUELocationRequested == nil {
		return nil, false
	}
	return v.rowCoarseUELocationRequested, true
}
func (v InitialUEMessageIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InitialUEMessageIEValue, error) {
	out := InitialUEMessageIEValue{id: id}
	switch id {
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
	case s00.ProtocolIEID(26):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NASPDU, error) {
			var v struct{ Value s00.NASPDU }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.NASPDU(val_value)
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
		out.rowNASPDU = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(67):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.TAI
		child := scope
		if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s31.BridgeTAIFieldPerPadding(&value) = padding
		*s31.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeTAIFieldReceivedBytes(&value))
		*s31.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s17.EUTRANCGI
		child := scope
		if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		*s17.BridgeEUTRANCGIFieldPerPadding(&value) = padding
		*s17.BridgeEUTRANCGIFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeEUTRANCGIFieldReceivedBytes(&value))
		*s17.BridgeEUTRANCGIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(134):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 3, Path: "RRCEstablishmentCause"})
		value := s00.RRCEstablishmentCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RRCEstablishmentCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRRCEstablishmentCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(96):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s27.STMSI
		child := scope
		if err := s27.BridgeSTMSIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "STMSI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "STMSI")
		if err != nil {
			return out, err
		}
		*s27.BridgeSTMSIFieldPerPadding(&value) = padding
		*s27.BridgeSTMSIFieldReceived(&value) = true
		raw.RetainContents(s27.BridgeSTMSIFieldReceivedBytes(&value))
		*s27.BridgeSTMSIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSTMSI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(127):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CSGId, error) {
			var v struct{ Value s00.CSGId }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 27, 27, true)
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
		out.rowCSGId = &value
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
	case s00.ProtocolIEID(145):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CellAccessMode"})
		value := s00.CellAccessMode(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CellAccessMode:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCellAccessMode = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(155):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowGWTransportLayerAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(160):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "RelayNodeIndicator"})
		value := s00.RelayNodeIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RelayNodeIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRelayNodeIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(170):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 1, Path: "GUMMEIType"})
		value := s00.GUMMEIType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "GUMMEIType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowGUMMEIType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(176):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s34.TunnelInformation
		child := scope
		if err := s34.BridgeTunnelInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		*s34.BridgeTunnelInformationFieldPerPadding(&value) = padding
		*s34.BridgeTunnelInformationFieldReceived(&value) = true
		raw.RetainContents(s34.BridgeTunnelInformationFieldReceivedBytes(&value))
		*s34.BridgeTunnelInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTunnelInformationForBBF = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(184):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.TransportLayerAddress, error) {
			var v struct{ Value s00.TransportLayerAddress }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
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
		out.rowSIPTOLGWTransportLayerAddress = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(186):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.LHNID, error) {
			var v struct{ Value s00.LHNID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 32, 256, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.LHNID(val_value)
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
		out.rowLHNID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(223):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MMEGroupID, error) {
			var v struct{ Value s00.MMEGroupID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.MMEGroupID(val_value)
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
		out.rowMMEGroupID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(230):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
		value := s00.UEUsageType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEUsageType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEUsageType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(242):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBSupportIndicator"})
		value := s00.CEModeBSupportIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBSupportIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBSupportIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(246):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
		value := s00.DCNID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DCNID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDCNID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(250):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CoverageLevel"})
		value := s00.CoverageLevel(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CoverageLevel:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCoverageLevel = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(263):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UEApplicationLayerMeasurementCapability, error) {
			var v struct {
				Value s00.UEApplicationLayerMeasurementCapability
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
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
		out.rowUEApplicationLayerMeasurementCapability = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(281):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EDTSession"})
		value := s00.EDTSession(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EDTSession:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEDTSession = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(302):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IABNodeIndication"})
		value := s00.IABNodeIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IABNodeIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIABNodeIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(339):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.LTENTNTAIInformation
		child := scope
		if err := s18.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s18.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s18.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s18.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowLTENTNTAIInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(353):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CoarseUELocationRequested"})
		value := s00.CoarseUELocationRequested(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CoarseUELocationRequested:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCoarseUELocationRequested = &value
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
func (v InitialUEMessageIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v InitialUEMessageIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(26):
		if v.rowNASPDU == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-NAS-PDU:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NASPDU, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.NASPDU }{Value: value}
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
		})(*v.rowNASPDU, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(67):
		if v.rowTAI == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-EUTRAN-CGI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s17.BridgeEUTRANCGIMethodMarshalAPERBudget(v.rowEUTRANCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(134):
		if v.rowRRCEstablishmentCause == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-RRC-Establishment-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRRCEstablishmentCause), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s27.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-CSG-Id:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CSGId, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CSGId }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 27, 27, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCSGId, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(75):
		if v.rowGUMMEIID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-GUMMEI-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGUMMEIMethodMarshalAPERBudget(v.rowGUMMEIID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(145):
		if v.rowCellAccessMode == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-CellAccessMode:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCellAccessMode), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(155):
		if v.rowGWTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-GW-TransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowGWTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(160):
		if v.rowRelayNodeIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-RelayNode-Indicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowRelayNodeIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(170):
		if v.rowGUMMEIType == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-GUMMEIType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowGUMMEIType), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(176):
		if v.rowTunnelInformationForBBF == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-Tunnel-Information-for-BBF:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s34.BridgeTunnelInformationMethodMarshalAPERBudget(v.rowTunnelInformationForBBF, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(184):
		if v.rowSIPTOLGWTransportLayerAddress == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-SIPTO-L-GW-TransportLayerAddress:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.TransportLayerAddress, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.TransportLayerAddress }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 1, 160, true, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSIPTOLGWTransportLayerAddress, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(186):
		if v.rowLHNID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-LHN-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.LHNID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.LHNID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 32, 256, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLHNID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(223):
		if v.rowMMEGroupID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-MME-Group-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MMEGroupID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MMEGroupID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMMEGroupID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(230):
		if v.rowUEUsageType == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-UE-Usage-Type:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowUEUsageType), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(242):
		if v.rowCEModeBSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-CE-mode-B-SupportIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBSupportIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(246):
		if v.rowDCNID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-DCN-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowDCNID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(250):
		if v.rowCoverageLevel == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-Coverage-Level:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCoverageLevel), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(263):
		if v.rowUEApplicationLayerMeasurementCapability == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-UE-Application-Layer-Measurement-Capability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UEApplicationLayerMeasurementCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.UEApplicationLayerMeasurementCapability
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 8, 8, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUEApplicationLayerMeasurementCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(281):
		if v.rowEDTSession == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-EDT-Session:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEDTSession), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(302):
		if v.rowIABNodeIndication == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-IAB-Node-Indication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIABNodeIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-LTE-NTN-TAI-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(353):
		if v.rowCoarseUELocationRequested == nil {
			return nil, fmt.Errorf("%s missing value", "InitialUEMessage-IEs.id-CoarseUELocationRequested:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCoarseUELocationRequested), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "InitialUEMessageIEValue:", v.id)
	}
}

type UEAssociatedLogicalS1ConnectionItemResIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowUEAssociatedLogicalS1ConnectionItem *UEAssociatedLogicalS1ConnectionItem
}

func (v UEAssociatedLogicalS1ConnectionItemResIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(91):
		return v.rowUEAssociatedLogicalS1ConnectionItem != nil
	}
	return false
}
func (v *UEAssociatedLogicalS1ConnectionItemResIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEAssociatedLogicalS1ConnectionItemResIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemRes"}}
}
func (UEAssociatedLogicalS1ConnectionItemResIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(91):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
func (v *UEAssociatedLogicalS1ConnectionItemResIEValue) AsUEAssociatedLogicalS1ConnectionItem() (*UEAssociatedLogicalS1ConnectionItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(91) || v.rowUEAssociatedLogicalS1ConnectionItem == nil {
		return nil, false
	}
	return v.rowUEAssociatedLogicalS1ConnectionItem, true
}
func (v UEAssociatedLogicalS1ConnectionItemResIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResIEValue, error) {
	out := UEAssociatedLogicalS1ConnectionItemResIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(91):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value UEAssociatedLogicalS1ConnectionItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "UEAssociatedLogicalS1ConnectionItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAssociatedLogicalS1ConnectionItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowUEAssociatedLogicalS1ConnectionItem = &value
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
func (v UEAssociatedLogicalS1ConnectionItemResIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEAssociatedLogicalS1ConnectionItemResIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(91):
		if v.rowUEAssociatedLogicalS1ConnectionItem == nil {
			return nil, fmt.Errorf("%s missing value", "UE-associatedLogicalS1-ConnectionItemRes.id-UE-associatedLogicalS1-ConnectionItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowUEAssociatedLogicalS1ConnectionItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEAssociatedLogicalS1ConnectionItemResIEValue:", v.id)
	}
}

type UEAssociatedLogicalS1ConnectionItemResAckIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowUEAssociatedLogicalS1ConnectionItem *UEAssociatedLogicalS1ConnectionItem
}

func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(91):
		return v.rowUEAssociatedLogicalS1ConnectionItem != nil
	}
	return false
}
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEAssociatedLogicalS1ConnectionItemResAckIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemResAck"}}
}
func (UEAssociatedLogicalS1ConnectionItemResAckIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(91):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) AsUEAssociatedLogicalS1ConnectionItem() (*UEAssociatedLogicalS1ConnectionItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(91) || v.rowUEAssociatedLogicalS1ConnectionItem == nil {
		return nil, false
	}
	return v.rowUEAssociatedLogicalS1ConnectionItem, true
}
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResAckIEValue, error) {
	out := UEAssociatedLogicalS1ConnectionItemResAckIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(91):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value UEAssociatedLogicalS1ConnectionItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "UEAssociatedLogicalS1ConnectionItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAssociatedLogicalS1ConnectionItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowUEAssociatedLogicalS1ConnectionItem = &value
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
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v UEAssociatedLogicalS1ConnectionItemResAckIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(91):
		if v.rowUEAssociatedLogicalS1ConnectionItem == nil {
			return nil, fmt.Errorf("%s missing value", "UE-associatedLogicalS1-ConnectionItemResAck.id-UE-associatedLogicalS1-ConnectionItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowUEAssociatedLogicalS1ConnectionItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEAssociatedLogicalS1ConnectionItemResAckIEValue:", v.id)
	}
}

type HandoverNotifyIETable struct{}

func HandoverNotifyIEs() HandoverNotifyIETable { return HandoverNotifyIETable{} }
func (HandoverNotifyIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs"}
		return sealed
	}()
}
func (HandoverNotifyIETable) Table() s00.HandoverNotifyIEValueIETable {
	return func() s00.HandoverNotifyIEValueIETable {
		sealed := s00.HandoverNotifyIEValueIETable{}
		*s00.BridgeHandoverNotifyIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverNotifyIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t HandoverNotifyIETable) MMEUES1APID() HandoverNotifyMMEUES1APIDIEBinding {
	return HandoverNotifyMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverNotifyIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t HandoverNotifyIETable) ENBUES1APID() HandoverNotifyENBUES1APIDIEBinding {
	return HandoverNotifyENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverNotifyIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-EUTRAN-CGI"}}}
}
func (t HandoverNotifyIETable) EUTRANCGI() HandoverNotifyEUTRANCGIIEBinding {
	return HandoverNotifyEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s17.EUTRANCGIValueCodec {
		sealed := s17.EUTRANCGIValueCodec{}
		*s17.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s17.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s17.EUTRANCGI, options aper.DecodeState) (s17.EUTRANCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s17.BridgeCaptureS1APEUTRANCGI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s17.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APEUTRANCGI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.EUTRANCGI) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (HandoverNotifyIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-TAI"}}}
}
func (t HandoverNotifyIETable) TAI() HandoverNotifyTAIIEBinding {
	return HandoverNotifyTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s31.TAI
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s31.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeTAIValueCodecFieldCapture(&sealed) = func(v s31.TAI, options aper.DecodeState) (s31.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s32.BridgeTAIValueCodecFieldCompare(&sealed) = func(v s31.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.TAI) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s31.TAI, bool) { return value.AsTAI() }}
}
func (HandoverNotifyIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-Tunnel-Information-for-BBF"}}}
}
func (t HandoverNotifyIETable) TunnelInformationForBBF() HandoverNotifyTunnelInformationIEBinding {
	return HandoverNotifyTunnelInformationIEBinding{info: t.infoTunnelInformationForBBF(), codec: TunnelInformationValueCodec{path: "TunnelInformation",
		decode: func(data []byte, options aper.DecodeState) (s34.TunnelInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s34.TunnelInformation
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(176), raw)
			if err != nil {
				var empty s34.TunnelInformation
				return empty, err
			}
			value, ok := decoded.AsTunnelInformationForBBF()
			if !ok {
				var empty s34.TunnelInformation
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-Tunnel-Information-for-BBF: no selected value")
			}
			return *value, nil
		},
		encode: func(value s34.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s34.TunnelInformation, options aper.DecodeState) (s34.TunnelInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s34.BridgeCaptureS1APTunnelInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}, compare: func(v s34.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s34.BridgeCompareS1APTunnelInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s34.TunnelInformation) HandoverNotifyIEValue {
		return HandoverNotifyIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}
	}, get: func(value *HandoverNotifyIEValue) (*s34.TunnelInformation, bool) {
		return value.AsTunnelInformationForBBF()
	}}
}
func (HandoverNotifyIETable) infoLHNID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(186), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LHN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-LHN-ID"}}}
}
func (t HandoverNotifyIETable) LHNID() HandoverNotifyLHNIDIEBinding {
	return HandoverNotifyLHNIDIEBinding{info: t.infoLHNID(), codec: func() s01.LHNIDValueCodec {
		sealed := s01.LHNIDValueCodec{}
		*s01.BridgeLHNIDValueCodecFieldPath(&sealed) = "LHNID"
		*s01.BridgeLHNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LHNID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(186), raw)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			value, ok := decoded.AsLHNID()
			if !ok {
				var empty s00.LHNID
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-LHN-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLHNIDValueCodecFieldEncode(&sealed) = func(value s00.LHNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeLHNIDValueCodecFieldCapture(&sealed) = func(v s00.LHNID, options aper.DecodeState) (s00.LHNID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLHNID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeLHNIDValueCodecFieldCompare(&sealed) = func(v s00.LHNID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APLHNID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLHNIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LHNID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.LHNID) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s00.LHNID, bool) { return value.AsLHNID() }}
}
func (HandoverNotifyIETable) infoPSCellInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(288), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PSCellInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-PSCellInformation"}}}
}
func (t HandoverNotifyIETable) PSCellInformation() HandoverNotifyPSCellInformationIEBinding {
	return HandoverNotifyPSCellInformationIEBinding{info: t.infoPSCellInformation(), codec: func() s20.PSCellInformationValueCodec {
		sealed := s20.PSCellInformationValueCodec{}
		*s20.BridgePSCellInformationValueCodecFieldPath(&sealed) = "PSCellInformation"
		*s20.BridgePSCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PSCellInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, err
			}
			value, ok := decoded.AsPSCellInformation()
			if !ok {
				var empty s20.PSCellInformation
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-PSCellInformation: no selected value")
			}
			return *value, nil
		}
		*s20.BridgePSCellInformationValueCodecFieldEncode(&sealed) = func(value s20.PSCellInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgePSCellInformationValueCodecFieldCapture(&sealed) = func(v s20.PSCellInformation, options aper.DecodeState) (s20.PSCellInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APPSCellInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s20.BridgePSCellInformationValueCodecFieldCompare(&sealed) = func(v s20.PSCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APPSCellInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgePSCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PSCellInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.PSCellInformation) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(288), rowPSCellInformation: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s20.PSCellInformation, bool) { return value.AsPSCellInformation() }}
}
func (HandoverNotifyIETable) infoNotifySourceeNB() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(320), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NotifySourceeNB"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-NotifySourceeNB"}}}
}
func (t HandoverNotifyIETable) NotifySourceeNB() HandoverNotifyNotifySourceeNBIEBinding {
	return HandoverNotifyNotifySourceeNBIEBinding{info: t.infoNotifySourceeNB(), codec: func() s01.NotifySourceeNBValueCodec {
		sealed := s01.NotifySourceeNBValueCodec{}
		*s01.BridgeNotifySourceeNBValueCodecFieldPath(&sealed) = "NotifySourceeNB"
		*s01.BridgeNotifySourceeNBValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NotifySourceeNB, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NotifySourceeNB
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(320), raw)
			if err != nil {
				var empty s00.NotifySourceeNB
				return empty, err
			}
			value, ok := decoded.AsNotifySourceeNB()
			if !ok {
				var empty s00.NotifySourceeNB
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-NotifySourceeNB: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNotifySourceeNBValueCodecFieldEncode(&sealed) = func(value s00.NotifySourceeNB, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(320), rowNotifySourceeNB: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNotifySourceeNBValueCodecFieldCapture(&sealed) = func(v s00.NotifySourceeNB, options aper.DecodeState) (s00.NotifySourceeNB, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNotifySourceeNB(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNotifySourceeNBValueCodecFieldCompare(&sealed) = func(v s00.NotifySourceeNB, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNotifySourceeNB(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeNotifySourceeNBValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NotifySourceeNB"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NotifySourceeNB) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(320), rowNotifySourceeNB: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s00.NotifySourceeNB, bool) { return value.AsNotifySourceeNB() }}
}
func (HandoverNotifyIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}
func (t HandoverNotifyIETable) LTENTNTAIInformation() HandoverNotifyLTENTNTAIInformationIEBinding {
	return HandoverNotifyLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s18.LTENTNTAIInformation, options aper.DecodeState) (s18.LTENTNTAIInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s18.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.LTENTNTAIInformation) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}
func (t HandoverNotifyIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverNotifyIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(186):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-LHN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(288):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-PSCellInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(320):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-NotifySourceeNB requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return HandoverNotifyIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverNotifyIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverNotifyIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverNotifyIEField{Id: id, Criticality: criticality, Value: HandoverNotifyIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type InitialUEMessageIETable struct{}

func InitialUEMessageIEs() InitialUEMessageIETable { return InitialUEMessageIETable{} }
func (InitialUEMessageIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs"}
		return sealed
	}()
}
func (InitialUEMessageIETable) Table() s00.InitialUEMessageIEValueIETable {
	return func() s00.InitialUEMessageIEValueIETable {
		sealed := s00.InitialUEMessageIEValueIETable{}
		*s00.BridgeInitialUEMessageIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (InitialUEMessageIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t InitialUEMessageIETable) ENBUES1APID() InitialUEMessageENBUES1APIDIEBinding {
	return InitialUEMessageENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (InitialUEMessageIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-NAS-PDU"}}}
}
func (t InitialUEMessageIETable) NASPDU() InitialUEMessageNASPDUIEBinding {
	return InitialUEMessageNASPDUIEBinding{info: t.infoNASPDU(), codec: func() s01.NASPDUValueCodec {
		sealed := s01.NASPDUValueCodec{}
		*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
		*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(26), raw)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			value, ok := decoded.AsNASPDU()
			if !ok {
				var empty s00.NASPDU
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-NAS-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNASPDUValueCodecFieldCapture(&sealed) = func(v s00.NASPDU, options aper.DecodeState) (s00.NASPDU, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APNASPDU(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNASPDUValueCodecFieldCompare(&sealed) = func(v s00.NASPDU, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNASPDU(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNASPDUValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASPDU"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NASPDU) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }}
}
func (InitialUEMessageIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-TAI"}}}
}
func (t InitialUEMessageIETable) TAI() InitialUEMessageTAIIEBinding {
	return InitialUEMessageTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s31.TAI
				return empty, err
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s31.TAI
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s31.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeTAIValueCodecFieldCapture(&sealed) = func(v s31.TAI, options aper.DecodeState) (s31.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s32.BridgeTAIValueCodecFieldCompare(&sealed) = func(v s31.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.TAI) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s31.TAI, bool) { return value.AsTAI() }}
}
func (InitialUEMessageIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-EUTRAN-CGI"}}}
}
func (t InitialUEMessageIETable) EUTRANCGI() InitialUEMessageEUTRANCGIIEBinding {
	return InitialUEMessageEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s17.EUTRANCGIValueCodec {
		sealed := s17.EUTRANCGIValueCodec{}
		*s17.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s17.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s17.EUTRANCGI, options aper.DecodeState) (s17.EUTRANCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s17.BridgeCaptureS1APEUTRANCGI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s17.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APEUTRANCGI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.EUTRANCGI) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (InitialUEMessageIETable) infoRRCEstablishmentCause() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(134), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RRC-Establishment-Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-RRC-Establishment-Cause"}}}
}
func (t InitialUEMessageIETable) RRCEstablishmentCause() InitialUEMessageRRCEstablishmentCauseIEBinding {
	return InitialUEMessageRRCEstablishmentCauseIEBinding{info: t.infoRRCEstablishmentCause(), codec: func() s01.RRCEstablishmentCauseValueCodec {
		sealed := s01.RRCEstablishmentCauseValueCodec{}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldPath(&sealed) = "RRCEstablishmentCause"
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RRCEstablishmentCause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(134), raw)
			if err != nil {
				var empty s00.RRCEstablishmentCause
				return empty, err
			}
			value, ok := decoded.AsRRCEstablishmentCause()
			if !ok {
				var empty s00.RRCEstablishmentCause
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-RRC-Establishment-Cause: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&sealed) = func(value s00.RRCEstablishmentCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(134), rowRRCEstablishmentCause: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCapture(&sealed) = func(v s00.RRCEstablishmentCause, options aper.DecodeState) (s00.RRCEstablishmentCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRRCEstablishmentCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldCompare(&sealed) = func(v s00.RRCEstablishmentCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRRCEstablishmentCause(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRRCEstablishmentCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RRCEstablishmentCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RRCEstablishmentCause) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(134), rowRRCEstablishmentCause: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.RRCEstablishmentCause, bool) {
			return value.AsRRCEstablishmentCause()
		}}
}
func (InitialUEMessageIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-S-TMSI"}}}
}
func (t InitialUEMessageIETable) STMSI() InitialUEMessageSTMSIIEBinding {
	return InitialUEMessageSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s28.STMSIValueCodec {
		sealed := s28.STMSIValueCodec{}
		*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s27.STMSI
				return empty, err
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s27.STMSI
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s27.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSTMSIValueCodecFieldCapture(&sealed) = func(v s27.STMSI, options aper.DecodeState) (s27.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s27.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s28.BridgeSTMSIValueCodecFieldCompare(&sealed) = func(v s27.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s27.BridgeCompareS1APSTMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSTMSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:STMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s27.STMSI) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s27.STMSI, bool) { return value.AsSTMSI() }}
}
func (InitialUEMessageIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CSG-Id"}}}
}
func (t InitialUEMessageIETable) CSGId() InitialUEMessageCSGIdIEBinding {
	return InitialUEMessageCSGIdIEBinding{info: t.infoCSGId(), codec: func() s00.CSGIdValueCodec {
		sealed := s00.CSGIdValueCodec{}
		*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
		*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGId
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(127), raw)
			if err != nil {
				var empty s00.CSGId
				return empty, err
			}
			value, ok := decoded.AsCSGId()
			if !ok {
				var empty s00.CSGId
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CSG-Id: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.CSGId) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }}
}
func (InitialUEMessageIETable) infoGUMMEIID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(75), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GUMMEI-ID"}}}
}
func (t InitialUEMessageIETable) GUMMEIID() InitialUEMessageGUMMEIIEBinding {
	return InitialUEMessageGUMMEIIEBinding{info: t.infoGUMMEIID(), codec: func() s18.GUMMEIValueCodec {
		sealed := s18.GUMMEIValueCodec{}
		*s18.BridgeGUMMEIValueCodecFieldPath(&sealed) = "GUMMEI"
		*s18.BridgeGUMMEIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GUMMEI
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(75), raw)
			if err != nil {
				var empty s18.GUMMEI
				return empty, err
			}
			value, ok := decoded.AsGUMMEIID()
			if !ok {
				var empty s18.GUMMEI
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GUMMEI-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGUMMEIValueCodecFieldEncode(&sealed) = func(value s18.GUMMEI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(75), rowGUMMEIID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.GUMMEI) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(75), rowGUMMEIID: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s18.GUMMEI, bool) { return value.AsGUMMEIID() }}
}
func (InitialUEMessageIETable) infoCellAccessMode() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(145), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellAccessMode"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CellAccessMode"}}}
}
func (t InitialUEMessageIETable) CellAccessMode() InitialUEMessageCellAccessModeIEBinding {
	return InitialUEMessageCellAccessModeIEBinding{info: t.infoCellAccessMode(), codec: func() s00.CellAccessModeValueCodec {
		sealed := s00.CellAccessModeValueCodec{}
		*s00.BridgeCellAccessModeValueCodecFieldPath(&sealed) = "CellAccessMode"
		*s00.BridgeCellAccessModeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellAccessMode, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(145), raw)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
			}
			value, ok := decoded.AsCellAccessMode()
			if !ok {
				var empty s00.CellAccessMode
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CellAccessMode: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellAccessModeValueCodecFieldEncode(&sealed) = func(value s00.CellAccessMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCellAccessModeValueCodecFieldCapture(&sealed) = func(v s00.CellAccessMode, options aper.DecodeState) (s00.CellAccessMode, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellAccessMode(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellAccessModeValueCodecFieldCompare(&sealed) = func(v s00.CellAccessMode, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCellAccessMode(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCellAccessModeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellAccessMode"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CellAccessMode) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.CellAccessMode, bool) { return value.AsCellAccessMode() }}
}
func (InitialUEMessageIETable) infoGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(155), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GW-TransportLayerAddress"}}}
}
func (t InitialUEMessageIETable) GWTransportLayerAddress() InitialUEMessageTransportLayerAddressIEBinding {
	return InitialUEMessageTransportLayerAddressIEBinding{info: t.infoGWTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(155), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			value, ok := decoded.AsGWTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GW-TransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(155), rowGWTransportLayerAddress: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTransportLayerAddress(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TransportLayerAddress) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(155), rowGWTransportLayerAddress: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsGWTransportLayerAddress()
		}}
}
func (InitialUEMessageIETable) infoRelayNodeIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(160), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RelayNode-Indicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-RelayNode-Indicator"}}}
}
func (t InitialUEMessageIETable) RelayNodeIndicator() InitialUEMessageRelayNodeIndicatorIEBinding {
	return InitialUEMessageRelayNodeIndicatorIEBinding{info: t.infoRelayNodeIndicator(), codec: func() s01.RelayNodeIndicatorValueCodec {
		sealed := s01.RelayNodeIndicatorValueCodec{}
		*s01.BridgeRelayNodeIndicatorValueCodecFieldPath(&sealed) = "RelayNodeIndicator"
		*s01.BridgeRelayNodeIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelayNodeIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RelayNodeIndicator
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(160), raw)
			if err != nil {
				var empty s00.RelayNodeIndicator
				return empty, err
			}
			value, ok := decoded.AsRelayNodeIndicator()
			if !ok {
				var empty s00.RelayNodeIndicator
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-RelayNode-Indicator: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRelayNodeIndicatorValueCodecFieldEncode(&sealed) = func(value s00.RelayNodeIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(160), rowRelayNodeIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRelayNodeIndicatorValueCodecFieldCapture(&sealed) = func(v s00.RelayNodeIndicator, options aper.DecodeState) (s00.RelayNodeIndicator, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APRelayNodeIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeRelayNodeIndicatorValueCodecFieldCompare(&sealed) = func(v s00.RelayNodeIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRelayNodeIndicator(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeRelayNodeIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RelayNodeIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RelayNodeIndicator) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(160), rowRelayNodeIndicator: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.RelayNodeIndicator, bool) {
			return value.AsRelayNodeIndicator()
		}}
}
func (InitialUEMessageIETable) infoGUMMEIType() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(170), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEIType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GUMMEIType"}}}
}
func (t InitialUEMessageIETable) GUMMEIType() InitialUEMessageGUMMEITypeIEBinding {
	return InitialUEMessageGUMMEITypeIEBinding{info: t.infoGUMMEIType(), codec: func() s00.GUMMEITypeValueCodec {
		sealed := s00.GUMMEITypeValueCodec{}
		*s00.BridgeGUMMEITypeValueCodecFieldPath(&sealed) = "GUMMEIType"
		*s00.BridgeGUMMEITypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GUMMEIType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.GUMMEIType
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(170), raw)
			if err != nil {
				var empty s00.GUMMEIType
				return empty, err
			}
			value, ok := decoded.AsGUMMEIType()
			if !ok {
				var empty s00.GUMMEIType
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GUMMEIType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeGUMMEITypeValueCodecFieldEncode(&sealed) = func(value s00.GUMMEIType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(170), rowGUMMEIType: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeGUMMEITypeValueCodecFieldCapture(&sealed) = func(v s00.GUMMEIType, options aper.DecodeState) (s00.GUMMEIType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APGUMMEIType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeGUMMEITypeValueCodecFieldCompare(&sealed) = func(v s00.GUMMEIType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APGUMMEIType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeGUMMEITypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEIType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.GUMMEIType) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(170), rowGUMMEIType: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.GUMMEIType, bool) { return value.AsGUMMEIType() }}
}
func (InitialUEMessageIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-Tunnel-Information-for-BBF"}}}
}
func (t InitialUEMessageIETable) TunnelInformationForBBF() InitialUEMessageTunnelInformationIEBinding {
	return InitialUEMessageTunnelInformationIEBinding{info: t.infoTunnelInformationForBBF(), codec: TunnelInformationValueCodec{path: "TunnelInformation",
		decode: func(data []byte, options aper.DecodeState) (s34.TunnelInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s34.TunnelInformation
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(176), raw)
			if err != nil {
				var empty s34.TunnelInformation
				return empty, err
			}
			value, ok := decoded.AsTunnelInformationForBBF()
			if !ok {
				var empty s34.TunnelInformation
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-Tunnel-Information-for-BBF: no selected value")
			}
			return *value, nil
		},
		encode: func(value s34.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s34.TunnelInformation, options aper.DecodeState) (s34.TunnelInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s34.BridgeCaptureS1APTunnelInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}, compare: func(v s34.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s34.BridgeCompareS1APTunnelInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s34.TunnelInformation) InitialUEMessageIEValue {
		return InitialUEMessageIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}
	}, get: func(value *InitialUEMessageIEValue) (*s34.TunnelInformation, bool) {
		return value.AsTunnelInformationForBBF()
	}}
}
func (InitialUEMessageIETable) infoSIPTOLGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(184), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-SIPTO-L-GW-TransportLayerAddress"}}}
}
func (t InitialUEMessageIETable) SIPTOLGWTransportLayerAddress() InitialUEMessageTransportLayerAddressIEBinding {
	return InitialUEMessageTransportLayerAddressIEBinding{info: t.infoSIPTOLGWTransportLayerAddress(), codec: func() s02.TransportLayerAddressValueCodec {
		sealed := s02.TransportLayerAddressValueCodec{}
		*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
		*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(184), raw)
			if err != nil {
				var empty s00.TransportLayerAddress
				return empty, err
			}
			value, ok := decoded.AsSIPTOLGWTransportLayerAddress()
			if !ok {
				var empty s00.TransportLayerAddress
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-SIPTO-L-GW-TransportLayerAddress: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(184), rowSIPTOLGWTransportLayerAddress: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCapture(&sealed) = func(v s00.TransportLayerAddress, options aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTransportLayerAddress(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldCompare(&sealed) = func(v s00.TransportLayerAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTransportLayerAddress(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTransportLayerAddressValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TransportLayerAddress"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TransportLayerAddress) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(184), rowSIPTOLGWTransportLayerAddress: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSIPTOLGWTransportLayerAddress()
		}}
}
func (InitialUEMessageIETable) infoLHNID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(186), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LHN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-LHN-ID"}}}
}
func (t InitialUEMessageIETable) LHNID() InitialUEMessageLHNIDIEBinding {
	return InitialUEMessageLHNIDIEBinding{info: t.infoLHNID(), codec: func() s01.LHNIDValueCodec {
		sealed := s01.LHNIDValueCodec{}
		*s01.BridgeLHNIDValueCodecFieldPath(&sealed) = "LHNID"
		*s01.BridgeLHNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LHNID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(186), raw)
			if err != nil {
				var empty s00.LHNID
				return empty, err
			}
			value, ok := decoded.AsLHNID()
			if !ok {
				var empty s00.LHNID
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-LHN-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeLHNIDValueCodecFieldEncode(&sealed) = func(value s00.LHNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeLHNIDValueCodecFieldCapture(&sealed) = func(v s00.LHNID, options aper.DecodeState) (s00.LHNID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLHNID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeLHNIDValueCodecFieldCompare(&sealed) = func(v s00.LHNID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APLHNID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLHNIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LHNID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.LHNID) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(186), rowLHNID: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.LHNID, bool) { return value.AsLHNID() }}
}
func (InitialUEMessageIETable) infoMMEGroupID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(223), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-Group-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-MME-Group-ID"}}}
}
func (t InitialUEMessageIETable) MMEGroupID() InitialUEMessageMMEGroupIDIEBinding {
	return InitialUEMessageMMEGroupIDIEBinding{info: t.infoMMEGroupID(), codec: func() s01.MMEGroupIDValueCodec {
		sealed := s01.MMEGroupIDValueCodec{}
		*s01.BridgeMMEGroupIDValueCodecFieldPath(&sealed) = "MMEGroupID"
		*s01.BridgeMMEGroupIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEGroupID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(223), raw)
			if err != nil {
				var empty s00.MMEGroupID
				return empty, err
			}
			value, ok := decoded.AsMMEGroupID()
			if !ok {
				var empty s00.MMEGroupID
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-MME-Group-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEGroupIDValueCodecFieldEncode(&sealed) = func(value s00.MMEGroupID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(223), rowMMEGroupID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCapture(&sealed) = func(v s00.MMEGroupID, options aper.DecodeState) (s00.MMEGroupID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMEGroupID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEGroupIDValueCodecFieldCompare(&sealed) = func(v s00.MMEGroupID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEGroupID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMEGroupIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEGroupID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEGroupID) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(223), rowMMEGroupID: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.MMEGroupID, bool) { return value.AsMMEGroupID() }}
}
func (InitialUEMessageIETable) infoUEUsageType() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(230), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Usage-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-UE-Usage-Type"}}}
}
func (t InitialUEMessageIETable) UEUsageType() InitialUEMessageUEUsageTypeIEBinding {
	return InitialUEMessageUEUsageTypeIEBinding{info: t.infoUEUsageType(), codec: func() s02.UEUsageTypeValueCodec {
		sealed := s02.UEUsageTypeValueCodec{}
		*s02.BridgeUEUsageTypeValueCodecFieldPath(&sealed) = "UEUsageType"
		*s02.BridgeUEUsageTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUsageType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUsageType
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(230), raw)
			if err != nil {
				var empty s00.UEUsageType
				return empty, err
			}
			value, ok := decoded.AsUEUsageType()
			if !ok {
				var empty s00.UEUsageType
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-UE-Usage-Type: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUsageTypeValueCodecFieldEncode(&sealed) = func(value s00.UEUsageType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(230), rowUEUsageType: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCapture(&sealed) = func(v s00.UEUsageType, options aper.DecodeState) (s00.UEUsageType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEUsageType(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEUsageTypeValueCodecFieldCompare(&sealed) = func(v s00.UEUsageType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEUsageType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeUEUsageTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUsageType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEUsageType) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(230), rowUEUsageType: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.UEUsageType, bool) { return value.AsUEUsageType() }}
}
func (InitialUEMessageIETable) infoCEModeBSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(242), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-mode-B-SupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CE-mode-B-SupportIndicator"}}}
}
func (t InitialUEMessageIETable) CEModeBSupportIndicator() InitialUEMessageCEModeBSupportIndicatorIEBinding {
	return InitialUEMessageCEModeBSupportIndicatorIEBinding{info: t.infoCEModeBSupportIndicator(), codec: func() s00.CEModeBSupportIndicatorValueCodec {
		sealed := s00.CEModeBSupportIndicatorValueCodec{}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldPath(&sealed) = "CEModeBSupportIndicator"
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBSupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBSupportIndicator
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(242), raw)
			if err != nil {
				var empty s00.CEModeBSupportIndicator
				return empty, err
			}
			value, ok := decoded.AsCEModeBSupportIndicator()
			if !ok {
				var empty s00.CEModeBSupportIndicator
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CE-mode-B-SupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CEModeBSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(242), rowCEModeBSupportIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.CEModeBSupportIndicator, options aper.DecodeState) (s00.CEModeBSupportIndicator, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBSupportIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.CEModeBSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBSupportIndicator(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBSupportIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBSupportIndicator) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(242), rowCEModeBSupportIndicator: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.CEModeBSupportIndicator, bool) {
			return value.AsCEModeBSupportIndicator()
		}}
}
func (InitialUEMessageIETable) infoDCNID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(246), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DCN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-DCN-ID"}}}
}
func (t InitialUEMessageIETable) DCNID() InitialUEMessageDCNIDIEBinding {
	return InitialUEMessageDCNIDIEBinding{info: t.infoDCNID(), codec: func() s00.DCNIDValueCodec {
		sealed := s00.DCNIDValueCodec{}
		*s00.BridgeDCNIDValueCodecFieldPath(&sealed) = "DCNID"
		*s00.BridgeDCNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DCNID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DCNID
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(246), raw)
			if err != nil {
				var empty s00.DCNID
				return empty, err
			}
			value, ok := decoded.AsDCNID()
			if !ok {
				var empty s00.DCNID
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-DCN-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDCNIDValueCodecFieldEncode(&sealed) = func(value s00.DCNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(246), rowDCNID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDCNIDValueCodecFieldCapture(&sealed) = func(v s00.DCNID, options aper.DecodeState) (s00.DCNID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APDCNID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s00.BridgeDCNIDValueCodecFieldCompare(&sealed) = func(v s00.DCNID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDCNID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDCNIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DCNID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DCNID) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(246), rowDCNID: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.DCNID, bool) { return value.AsDCNID() }}
}
func (InitialUEMessageIETable) infoCoverageLevel() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(250), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Coverage-Level"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-Coverage-Level"}}}
}
func (t InitialUEMessageIETable) CoverageLevel() InitialUEMessageCoverageLevelIEBinding {
	return InitialUEMessageCoverageLevelIEBinding{info: t.infoCoverageLevel(), codec: func() s00.CoverageLevelValueCodec {
		sealed := s00.CoverageLevelValueCodec{}
		*s00.BridgeCoverageLevelValueCodecFieldPath(&sealed) = "CoverageLevel"
		*s00.BridgeCoverageLevelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoverageLevel, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CoverageLevel
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(250), raw)
			if err != nil {
				var empty s00.CoverageLevel
				return empty, err
			}
			value, ok := decoded.AsCoverageLevel()
			if !ok {
				var empty s00.CoverageLevel
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-Coverage-Level: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCoverageLevelValueCodecFieldEncode(&sealed) = func(value s00.CoverageLevel, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(250), rowCoverageLevel: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCoverageLevelValueCodecFieldCapture(&sealed) = func(v s00.CoverageLevel, options aper.DecodeState) (s00.CoverageLevel, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCoverageLevel(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCoverageLevelValueCodecFieldCompare(&sealed) = func(v s00.CoverageLevel, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCoverageLevel(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeCoverageLevelValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CoverageLevel"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CoverageLevel) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(250), rowCoverageLevel: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.CoverageLevel, bool) { return value.AsCoverageLevel() }}
}
func (InitialUEMessageIETable) infoUEApplicationLayerMeasurementCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(263), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Application-Layer-Measurement-Capability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-UE-Application-Layer-Measurement-Capability"}}}
}
func (t InitialUEMessageIETable) UEApplicationLayerMeasurementCapability() InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding {
	return InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding{info: t.infoUEApplicationLayerMeasurementCapability(), codec: func() s02.UEApplicationLayerMeasurementCapabilityValueCodec {
		sealed := s02.UEApplicationLayerMeasurementCapabilityValueCodec{}
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldPath(&sealed) = "UEApplicationLayerMeasurementCapability"
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEApplicationLayerMeasurementCapability
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(263), raw)
			if err != nil {
				var empty s00.UEApplicationLayerMeasurementCapability
				return empty, err
			}
			value, ok := decoded.AsUEApplicationLayerMeasurementCapability()
			if !ok {
				var empty s00.UEApplicationLayerMeasurementCapability
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-UE-Application-Layer-Measurement-Capability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UEApplicationLayerMeasurementCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(263), rowUEApplicationLayerMeasurementCapability: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldCapture(&sealed) = func(v s00.UEApplicationLayerMeasurementCapability, options aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEApplicationLayerMeasurementCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldCompare(&sealed) = func(v s00.UEApplicationLayerMeasurementCapability, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEApplicationLayerMeasurementCapability(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEApplicationLayerMeasurementCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEApplicationLayerMeasurementCapability) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(263), rowUEApplicationLayerMeasurementCapability: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.UEApplicationLayerMeasurementCapability, bool) {
			return value.AsUEApplicationLayerMeasurementCapability()
		}}
}
func (InitialUEMessageIETable) infoEDTSession() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(281), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EDT-Session"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-EDT-Session"}}}
}
func (t InitialUEMessageIETable) EDTSession() InitialUEMessageEDTSessionIEBinding {
	return InitialUEMessageEDTSessionIEBinding{info: t.infoEDTSession(), codec: func() s00.EDTSessionValueCodec {
		sealed := s00.EDTSessionValueCodec{}
		*s00.BridgeEDTSessionValueCodecFieldPath(&sealed) = "EDTSession"
		*s00.BridgeEDTSessionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EDTSession, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EDTSession
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(281), raw)
			if err != nil {
				var empty s00.EDTSession
				return empty, err
			}
			value, ok := decoded.AsEDTSession()
			if !ok {
				var empty s00.EDTSession
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-EDT-Session: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEDTSessionValueCodecFieldEncode(&sealed) = func(value s00.EDTSession, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(281), rowEDTSession: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEDTSessionValueCodecFieldCapture(&sealed) = func(v s00.EDTSession, options aper.DecodeState) (s00.EDTSession, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APEDTSession(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEDTSessionValueCodecFieldCompare(&sealed) = func(v s00.EDTSession, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEDTSession(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEDTSessionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EDTSession"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EDTSession) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(281), rowEDTSession: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.EDTSession, bool) { return value.AsEDTSession() }}
}
func (InitialUEMessageIETable) infoIABNodeIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(302), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Node-Indication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-IAB-Node-Indication"}}}
}
func (t InitialUEMessageIETable) IABNodeIndication() InitialUEMessageIABNodeIndicationIEBinding {
	return InitialUEMessageIABNodeIndicationIEBinding{info: t.infoIABNodeIndication(), codec: func() s01.IABNodeIndicationValueCodec {
		sealed := s01.IABNodeIndicationValueCodec{}
		*s01.BridgeIABNodeIndicationValueCodecFieldPath(&sealed) = "IABNodeIndication"
		*s01.BridgeIABNodeIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABNodeIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IABNodeIndication
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(302), raw)
			if err != nil {
				var empty s00.IABNodeIndication
				return empty, err
			}
			value, ok := decoded.AsIABNodeIndication()
			if !ok {
				var empty s00.IABNodeIndication
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-IAB-Node-Indication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeIABNodeIndicationValueCodecFieldEncode(&sealed) = func(value s00.IABNodeIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(302), rowIABNodeIndication: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeIABNodeIndicationValueCodecFieldCapture(&sealed) = func(v s00.IABNodeIndication, options aper.DecodeState) (s00.IABNodeIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIABNodeIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeIABNodeIndicationValueCodecFieldCompare(&sealed) = func(v s00.IABNodeIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIABNodeIndication(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeIABNodeIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABNodeIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IABNodeIndication) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(302), rowIABNodeIndication: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.IABNodeIndication, bool) {
			return value.AsIABNodeIndication()
		}}
}
func (InitialUEMessageIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-LTE-NTN-TAI-Information"}}}
}
func (t InitialUEMessageIETable) LTENTNTAIInformation() InitialUEMessageLTENTNTAIInformationIEBinding {
	return InitialUEMessageLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s18.LTENTNTAIInformation, options aper.DecodeState) (s18.LTENTNTAIInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s18.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.LTENTNTAIInformation) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}
func (InitialUEMessageIETable) infoCoarseUELocationRequested() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(353), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocationRequested"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CoarseUELocationRequested"}}}
}
func (t InitialUEMessageIETable) CoarseUELocationRequested() InitialUEMessageCoarseUELocationRequestedIEBinding {
	return InitialUEMessageCoarseUELocationRequestedIEBinding{info: t.infoCoarseUELocationRequested(), codec: func() s00.CoarseUELocationRequestedValueCodec {
		sealed := s00.CoarseUELocationRequestedValueCodec{}
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldPath(&sealed) = "CoarseUELocationRequested"
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocationRequested, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CoarseUELocationRequested
				return empty, err
			}
			var zero InitialUEMessageIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(353), raw)
			if err != nil {
				var empty s00.CoarseUELocationRequested
				return empty, err
			}
			value, ok := decoded.AsCoarseUELocationRequested()
			if !ok {
				var empty s00.CoarseUELocationRequested
				return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CoarseUELocationRequested: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocationRequested, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialUEMessageIEValue{id: s00.ProtocolIEID(353), rowCoarseUELocationRequested: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldCapture(&sealed) = func(v s00.CoarseUELocationRequested, options aper.DecodeState) (s00.CoarseUELocationRequested, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCoarseUELocationRequested(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldCompare(&sealed) = func(v s00.CoarseUELocationRequested, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCoarseUELocationRequested(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCoarseUELocationRequestedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CoarseUELocationRequested"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CoarseUELocationRequested) InitialUEMessageIEValue {
			return InitialUEMessageIEValue{id: s00.ProtocolIEID(353), rowCoarseUELocationRequested: &value}
		}, get: func(value *InitialUEMessageIEValue) (*s00.CoarseUELocationRequested, bool) {
			return value.AsCoarseUELocationRequested()
		}}
}
func (t InitialUEMessageIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (InitialUEMessageIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(134):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-RRC-Establishment-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(96):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(75):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEI-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(145):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellAccessMode requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(155):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(160):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-RelayNode-Indicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(170):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEIType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(184):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-SIPTO-L-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(186):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-LHN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(223):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-Group-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(230):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Usage-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(242):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-mode-B-SupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(246):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-DCN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(250):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-Coverage-Level requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(263):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Application-Layer-Measurement-Capability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(281):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-EDT-Session requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(302):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Node-Indication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(353):
		return InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocationRequested requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InitialUEMessageIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InitialUEMessageIEField{}, aper.OperationError(err, "Opaque")
		}
		return InitialUEMessageIEField{Id: id, Criticality: criticality, Value: InitialUEMessageIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEAssociatedLogicalS1ConnectionItemResTable struct{}

func UEAssociatedLogicalS1ConnectionItemRes() UEAssociatedLogicalS1ConnectionItemResTable {
	return UEAssociatedLogicalS1ConnectionItemResTable{}
}
func (UEAssociatedLogicalS1ConnectionItemResTable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemRes"}
		return sealed
	}()
}
func (UEAssociatedLogicalS1ConnectionItemResTable) Table() s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable {
	return func() s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable {
		sealed := s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable{}
		*s00.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEAssociatedLogicalS1ConnectionItemResTable) infoUEAssociatedLogicalS1ConnectionItem() s00.FieldInfo {
	return s00.FieldInfo{Table: UEAssociatedLogicalS1ConnectionItemRes().ID(), ID: s00.ProtocolIEID(91), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-associatedLogicalS1-ConnectionItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemRes", Row: "id-UE-associatedLogicalS1-ConnectionItem"}}}
}
func (t UEAssociatedLogicalS1ConnectionItemResTable) UEAssociatedLogicalS1ConnectionItem() UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding {
	return UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionItem(), codec: UEAssociatedLogicalS1ConnectionItemValueCodec{path: "UEAssociatedLogicalS1ConnectionItem",
		decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			var zero UEAssociatedLogicalS1ConnectionItemResIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(91), raw)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			value, ok := decoded.AsUEAssociatedLogicalS1ConnectionItem()
			if !ok {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, fmt.Errorf("binding UE-associatedLogicalS1-ConnectionItemRes.id-UE-associatedLogicalS1-ConnectionItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value UEAssociatedLogicalS1ConnectionItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEAssociatedLogicalS1ConnectionItemResIEValue{id: s00.ProtocolIEID(91), rowUEAssociatedLogicalS1ConnectionItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v UEAssociatedLogicalS1ConnectionItem, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}, compare: func(v UEAssociatedLogicalS1ConnectionItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value UEAssociatedLogicalS1ConnectionItem) UEAssociatedLogicalS1ConnectionItemResIEValue {
		return UEAssociatedLogicalS1ConnectionItemResIEValue{id: s00.ProtocolIEID(91), rowUEAssociatedLogicalS1ConnectionItem: &value}
	}, get: func(value *UEAssociatedLogicalS1ConnectionItemResIEValue) (*UEAssociatedLogicalS1ConnectionItem, bool) {
		return value.AsUEAssociatedLogicalS1ConnectionItem()
	}}
}
func (t UEAssociatedLogicalS1ConnectionItemResTable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEAssociatedLogicalS1ConnectionItemResIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(91):
		return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-associatedLogicalS1-ConnectionItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEAssociatedLogicalS1ConnectionItemResIEField{Id: id, Criticality: criticality, Value: UEAssociatedLogicalS1ConnectionItemResIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEAssociatedLogicalS1ConnectionItemResAckTable struct{}

func UEAssociatedLogicalS1ConnectionItemResAck() UEAssociatedLogicalS1ConnectionItemResAckTable {
	return UEAssociatedLogicalS1ConnectionItemResAckTable{}
}
func (UEAssociatedLogicalS1ConnectionItemResAckTable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemResAck"}
		return sealed
	}()
}
func (UEAssociatedLogicalS1ConnectionItemResAckTable) Table() s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable {
	return func() s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable {
		sealed := s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable{}
		*s00.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEAssociatedLogicalS1ConnectionItemResAckTable) infoUEAssociatedLogicalS1ConnectionItem() s00.FieldInfo {
	return s00.FieldInfo{Table: UEAssociatedLogicalS1ConnectionItemResAck().ID(), ID: s00.ProtocolIEID(91), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-associatedLogicalS1-ConnectionItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemResAck", Row: "id-UE-associatedLogicalS1-ConnectionItem"}}}
}
func (t UEAssociatedLogicalS1ConnectionItemResAckTable) UEAssociatedLogicalS1ConnectionItem() UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding {
	return UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionItem(), codec: UEAssociatedLogicalS1ConnectionItemValueCodec{path: "UEAssociatedLogicalS1ConnectionItem",
		decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			var zero UEAssociatedLogicalS1ConnectionItemResAckIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(91), raw)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			value, ok := decoded.AsUEAssociatedLogicalS1ConnectionItem()
			if !ok {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, fmt.Errorf("binding UE-associatedLogicalS1-ConnectionItemResAck.id-UE-associatedLogicalS1-ConnectionItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value UEAssociatedLogicalS1ConnectionItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEAssociatedLogicalS1ConnectionItemResAckIEValue{id: s00.ProtocolIEID(91), rowUEAssociatedLogicalS1ConnectionItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v UEAssociatedLogicalS1ConnectionItem, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APUEAssociatedLogicalS1ConnectionItem(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}, compare: func(v UEAssociatedLogicalS1ConnectionItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUEAssociatedLogicalS1ConnectionItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value UEAssociatedLogicalS1ConnectionItem) UEAssociatedLogicalS1ConnectionItemResAckIEValue {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValue{id: s00.ProtocolIEID(91), rowUEAssociatedLogicalS1ConnectionItem: &value}
	}, get: func(value *UEAssociatedLogicalS1ConnectionItemResAckIEValue) (*UEAssociatedLogicalS1ConnectionItem, bool) {
		return value.AsUEAssociatedLogicalS1ConnectionItem()
	}}
}
func (t UEAssociatedLogicalS1ConnectionItemResAckTable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEAssociatedLogicalS1ConnectionItemResAckIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(91):
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-associatedLogicalS1-ConnectionItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEAssociatedLogicalS1ConnectionItemResAckIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEAssociatedLogicalS1ConnectionItemResAckIEField{Id: id, Criticality: criticality, Value: UEAssociatedLogicalS1ConnectionItemResAckIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CoarseUELocationRequestedCodec binds the complete APER value type.
func CoarseUELocationRequestedCodec() s00.CoarseUELocationRequestedValueCodec {
	return InitialUEMessageIEs().CoarseUELocationRequested().Codec()
}

// CoverageLevelCodec binds the complete APER value type.
func CoverageLevelCodec() s00.CoverageLevelValueCodec {
	return InitialUEMessageIEs().CoverageLevel().Codec()
}

// DCNIDCodec binds the complete APER value type.
func DCNIDCodec() s00.DCNIDValueCodec { return InitialUEMessageIEs().DCNID().Codec() }

// EDTSessionCodec binds the complete APER value type.
func EDTSessionCodec() s00.EDTSessionValueCodec { return InitialUEMessageIEs().EDTSession().Codec() }

// IABNodeIndicationCodec binds the complete APER value type.
func IABNodeIndicationCodec() s01.IABNodeIndicationValueCodec {
	return InitialUEMessageIEs().IABNodeIndication().Codec()
}

// LHNIDCodec binds the complete APER value type.
func LHNIDCodec() s01.LHNIDValueCodec { return HandoverNotifyIEs().LHNID().Codec() }

// MMEGroupIDCodec binds the complete APER value type.
func MMEGroupIDCodec() s01.MMEGroupIDValueCodec { return InitialUEMessageIEs().MMEGroupID().Codec() }

// NotifySourceeNBCodec binds the complete APER value type.
func NotifySourceeNBCodec() s01.NotifySourceeNBValueCodec {
	return HandoverNotifyIEs().NotifySourceeNB().Codec()
}

// RRCEstablishmentCauseCodec binds the complete APER value type.
func RRCEstablishmentCauseCodec() s01.RRCEstablishmentCauseValueCodec {
	return InitialUEMessageIEs().RRCEstablishmentCause().Codec()
}

// RelayNodeIndicatorCodec binds the complete APER value type.
func RelayNodeIndicatorCodec() s01.RelayNodeIndicatorValueCodec {
	return InitialUEMessageIEs().RelayNodeIndicator().Codec()
}

// UEApplicationLayerMeasurementCapabilityCodec binds the complete APER value type.
func UEApplicationLayerMeasurementCapabilityCodec() s02.UEApplicationLayerMeasurementCapabilityValueCodec {
	return InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Codec()
}

// UEAssociatedLogicalS1ConnectionItemCodec binds the complete APER value type.
func UEAssociatedLogicalS1ConnectionItemCodec() UEAssociatedLogicalS1ConnectionItemValueCodec {
	return UEAssociatedLogicalS1ConnectionItemRes().UEAssociatedLogicalS1ConnectionItem().Codec()
}

// UEUsageTypeCodec binds the complete APER value type.
func UEUsageTypeCodec() s02.UEUsageTypeValueCodec { return InitialUEMessageIEs().UEUsageType().Codec() }
func BridgeHandoverNotifyAPERValueFieldContext(v *HandoverNotifyAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyAPERValueFieldReceived(v *HandoverNotifyAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyAPERValueFieldReplay(v *HandoverNotifyAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyAPERValueFieldWithoutReplay(v *HandoverNotifyAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyENBUES1APIDIEBindingFieldCodec(v *HandoverNotifyENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyENBUES1APIDIEBindingFieldGet(v *HandoverNotifyENBUES1APIDIEBinding) *func(*HandoverNotifyIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverNotifyENBUES1APIDIEBindingFieldInfo(v *HandoverNotifyENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyENBUES1APIDIEBindingFieldInject(v *HandoverNotifyENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyEUTRANCGIIEBindingFieldCodec(v *HandoverNotifyEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyEUTRANCGIIEBindingFieldGet(v *HandoverNotifyEUTRANCGIIEBinding) *func(*HandoverNotifyIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgeHandoverNotifyEUTRANCGIIEBindingFieldInfo(v *HandoverNotifyEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyEUTRANCGIIEBindingFieldInject(v *HandoverNotifyEUTRANCGIIEBinding) *func(s17.EUTRANCGI) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyFieldExtCount(v *HandoverNotify) *int64                { return &v.extCount }
func BridgeHandoverNotifyFieldExtData(v *HandoverNotify) *[][]byte              { return &v.extData }
func BridgeHandoverNotifyFieldExtOrigin(v *HandoverNotify) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeHandoverNotifyFieldExtPresent(v *HandoverNotify) *[]bool             { return &v.extPresent }
func BridgeHandoverNotifyFieldExtWire(v *HandoverNotify) *[]aper.WireSpan       { return &v.extWire }
func BridgeHandoverNotifyFieldPerExtPadding(v *HandoverNotify) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverNotifyFieldPerPadding(v *HandoverNotify) *aper.FinalPadding { return &v.perPadding }
func BridgeHandoverNotifyFieldProtocolIEsIndef(v *HandoverNotify) *bool        { return &v.protocolIEsIndef }
func BridgeHandoverNotifyFieldReceived(v *HandoverNotify) *bool                { return &v.received }
func BridgeHandoverNotifyFieldReceivedAbsolute(v *HandoverNotify) *bool        { return &v.receivedAbsolute }
func BridgeHandoverNotifyFieldReceivedBytes(v *HandoverNotify) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverNotifyFieldReceivedLocation(v *HandoverNotify) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverNotifyFieldReplay(v *HandoverNotify) *aper.Snapshot { return &v.replay }
func BridgeHandoverNotifyFieldStream(v *HandoverNotify) *aper.WireSpan { return &v.stream }
func BridgeHandoverNotifyFieldWithoutReplay(v *HandoverNotify) *bool   { return &v.withoutReplay }
func BridgeHandoverNotifyIEContainerAPERValueFieldContext(v *HandoverNotifyIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEContainerAPERValueFieldReceived(v *HandoverNotifyIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEContainerAPERValueFieldReplay(v *HandoverNotifyIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEContainerAPERValueFieldWithoutReplay(v *HandoverNotifyIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEContainerValueCodecFieldCapture(v *HandoverNotifyIEContainerValueCodec) *func(HandoverNotifyIEContainer, aper.DecodeState) (HandoverNotifyIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyIEContainerValueCodecFieldCompare(v *HandoverNotifyIEContainerValueCodec) *func(HandoverNotifyIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyIEContainerValueCodecFieldContext(v *HandoverNotifyIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEContainerValueCodecFieldDecode(v *HandoverNotifyIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverNotifyIEContainer, error) {
	return &v.decode
}
func BridgeHandoverNotifyIEContainerValueCodecFieldEncode(v *HandoverNotifyIEContainerValueCodec) *func(HandoverNotifyIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyIEContainerValueCodecFieldPath(v *HandoverNotifyIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverNotifyIEContainerValueCodecMethodEncodeBudgetValue(v HandoverNotifyIEContainerValueCodec, a0 HandoverNotifyIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyIEContainerValueCodecMethodEncodeChanged(v HandoverNotifyIEContainerValueCodec, a0 HandoverNotifyIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverNotifyIEFieldAPERValueFieldContext(v *HandoverNotifyIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEFieldAPERValueFieldReceived(v *HandoverNotifyIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEFieldAPERValueFieldReplay(v *HandoverNotifyIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEFieldAPERValueFieldWithoutReplay(v *HandoverNotifyIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEFieldFieldReceived(v *HandoverNotifyIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverNotifyIEFieldFieldReplay(v *HandoverNotifyIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEFieldFieldStream(v *HandoverNotifyIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverNotifyIEFieldFieldWithoutReplay(v *HandoverNotifyIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(v *HandoverNotifyIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(v *HandoverNotifyIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverNotifyIEFieldValueCodecFieldCapture(v *HandoverNotifyIEFieldValueCodec) *func(HandoverNotifyIEField, aper.DecodeState) (HandoverNotifyIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyIEFieldValueCodecFieldCompare(v *HandoverNotifyIEFieldValueCodec) *func(HandoverNotifyIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyIEFieldValueCodecFieldContext(v *HandoverNotifyIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEFieldValueCodecFieldDecode(v *HandoverNotifyIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverNotifyIEField, error) {
	return &v.decode
}
func BridgeHandoverNotifyIEFieldValueCodecFieldEncode(v *HandoverNotifyIEFieldValueCodec) *func(HandoverNotifyIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyIEFieldValueCodecFieldPath(v *HandoverNotifyIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverNotifyIEFieldValueCodecMethodEncodeBudgetValue(v HandoverNotifyIEFieldValueCodec, a0 HandoverNotifyIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyIEFieldValueCodecMethodEncodeChanged(v HandoverNotifyIEFieldValueCodec, a0 HandoverNotifyIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverNotifyIETableMethodInfoENBUES1APID(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverNotifyIETableMethodInfoEUTRANCGI(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoEUTRANCGI()
}
func BridgeHandoverNotifyIETableMethodInfoLHNID(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoLHNID()
}
func BridgeHandoverNotifyIETableMethodInfoLTENTNTAIInformation(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgeHandoverNotifyIETableMethodInfoMMEUES1APID(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverNotifyIETableMethodInfoNotifySourceeNB(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoNotifySourceeNB()
}
func BridgeHandoverNotifyIETableMethodInfoPSCellInformation(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoPSCellInformation()
}
func BridgeHandoverNotifyIETableMethodInfoTAI(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoTAI()
}
func BridgeHandoverNotifyIETableMethodInfoTunnelInformationForBBF(v HandoverNotifyIETable) s00.FieldInfo {
	return v.infoTunnelInformationForBBF()
}
func BridgeHandoverNotifyIEValueERABIEContainerListAPERValueFieldContext(v *HandoverNotifyIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverNotifyIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverNotifyIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverNotifyIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *func(HandoverNotifyIEValueERABIEContainerList, aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *func(HandoverNotifyIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldContext(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverNotifyIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *func(HandoverNotifyIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldPath(v *HandoverNotifyIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverNotifyIEValueERABIEContainerListValueCodec, a0 HandoverNotifyIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverNotifyIEValueERABIEContainerListValueCodec, a0 HandoverNotifyIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverNotifyIEValueFieldId(v *HandoverNotifyIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverNotifyIEValueFieldIsOpaque(v *HandoverNotifyIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverNotifyIEValueFieldOpaque(v *HandoverNotifyIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverNotifyIEValueFieldReceived(v *HandoverNotifyIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEValueFieldReplay(v *HandoverNotifyIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEValueFieldRowENBUES1APID(v *HandoverNotifyIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverNotifyIEValueFieldRowEUTRANCGI(v *HandoverNotifyIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeHandoverNotifyIEValueFieldRowLHNID(v *HandoverNotifyIEValue) **s00.LHNID {
	return &v.rowLHNID
}
func BridgeHandoverNotifyIEValueFieldRowLTENTNTAIInformation(v *HandoverNotifyIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeHandoverNotifyIEValueFieldRowMMEUES1APID(v *HandoverNotifyIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverNotifyIEValueFieldRowNotifySourceeNB(v *HandoverNotifyIEValue) **s00.NotifySourceeNB {
	return &v.rowNotifySourceeNB
}
func BridgeHandoverNotifyIEValueFieldRowPSCellInformation(v *HandoverNotifyIEValue) **s20.PSCellInformation {
	return &v.rowPSCellInformation
}
func BridgeHandoverNotifyIEValueFieldRowTAI(v *HandoverNotifyIEValue) **s31.TAI { return &v.rowTAI }
func BridgeHandoverNotifyIEValueFieldRowTunnelInformationForBBF(v *HandoverNotifyIEValue) **s34.TunnelInformation {
	return &v.rowTunnelInformationForBBF
}
func BridgeHandoverNotifyIEValueMethodCaptureSemantics(v HandoverNotifyIEValue, a0 aper.SemanticCapture) HandoverNotifyIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverNotifyIEValueMethodCompareSemantics(v HandoverNotifyIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverNotifyIEValueMethodDecode(v HandoverNotifyIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverNotifyIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverNotifyIEValueMethodEncode(v HandoverNotifyIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverNotifyIEValueMethodEncodeFresh(v HandoverNotifyIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverNotifyIEValueMethodMatchesID(v HandoverNotifyIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverNotifyIEValueMethodReason(v HandoverNotifyIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverNotifyIEValueMethodRule(v HandoverNotifyIEValue) aper.SourceRule { return v.rule() }
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverNotifyIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverNotifyIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverNotifyIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverNotifyIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverNotifyIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverNotifyIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverNotifyIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolIEContainerList, aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverNotifyIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *func(HandoverNotifyIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverNotifyIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverNotifyIEValueProtocolIEContainerListValueCodec, a0 HandoverNotifyIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverNotifyIEValueProtocolIEContainerListValueCodec, a0 HandoverNotifyIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverNotifyLHNIDIEBindingFieldCodec(v *HandoverNotifyLHNIDIEBinding) *s01.LHNIDValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyLHNIDIEBindingFieldGet(v *HandoverNotifyLHNIDIEBinding) *func(*HandoverNotifyIEValue) (*s00.LHNID, bool) {
	return &v.get
}
func BridgeHandoverNotifyLHNIDIEBindingFieldInfo(v *HandoverNotifyLHNIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyLHNIDIEBindingFieldInject(v *HandoverNotifyLHNIDIEBinding) *func(s00.LHNID) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyLTENTNTAIInformationIEBindingFieldCodec(v *HandoverNotifyLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyLTENTNTAIInformationIEBindingFieldGet(v *HandoverNotifyLTENTNTAIInformationIEBinding) *func(*HandoverNotifyIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeHandoverNotifyLTENTNTAIInformationIEBindingFieldInfo(v *HandoverNotifyLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyLTENTNTAIInformationIEBindingFieldInject(v *HandoverNotifyLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyMMEUES1APIDIEBindingFieldCodec(v *HandoverNotifyMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyMMEUES1APIDIEBindingFieldGet(v *HandoverNotifyMMEUES1APIDIEBinding) *func(*HandoverNotifyIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverNotifyMMEUES1APIDIEBindingFieldInfo(v *HandoverNotifyMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyMMEUES1APIDIEBindingFieldInject(v *HandoverNotifyMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyMethodMarshalAPERBudget(v *HandoverNotify, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverNotifyMethodMarshalAPERBudgetValue(v *HandoverNotify, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverNotifyMethodMarshalAPERChanged(v *HandoverNotify, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverNotifyMethodMarshalAPERChangedValue(v *HandoverNotify, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverNotifyMethodMarshalAPERLegacy(v *HandoverNotify) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverNotifyMethodMarshalAPERNewValue(v *HandoverNotify, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverNotifyMethodMarshalAPERPlanned(v *HandoverNotify, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverNotifyMethodMarshalAPERTo(v *HandoverNotify, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverNotifyMethodUnmarshalAPERFrom(v *HandoverNotify, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverNotifyMethodUnmarshalAPERLegacy(v *HandoverNotify, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverNotifyMethodUnmarshalAPERWithOptions(v *HandoverNotify, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverNotifyNotifySourceeNBIEBindingFieldCodec(v *HandoverNotifyNotifySourceeNBIEBinding) *s01.NotifySourceeNBValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyNotifySourceeNBIEBindingFieldGet(v *HandoverNotifyNotifySourceeNBIEBinding) *func(*HandoverNotifyIEValue) (*s00.NotifySourceeNB, bool) {
	return &v.get
}
func BridgeHandoverNotifyNotifySourceeNBIEBindingFieldInfo(v *HandoverNotifyNotifySourceeNBIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyNotifySourceeNBIEBindingFieldInject(v *HandoverNotifyNotifySourceeNBIEBinding) *func(s00.NotifySourceeNB) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyPSCellInformationIEBindingFieldCodec(v *HandoverNotifyPSCellInformationIEBinding) *s20.PSCellInformationValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyPSCellInformationIEBindingFieldGet(v *HandoverNotifyPSCellInformationIEBinding) *func(*HandoverNotifyIEValue) (*s20.PSCellInformation, bool) {
	return &v.get
}
func BridgeHandoverNotifyPSCellInformationIEBindingFieldInfo(v *HandoverNotifyPSCellInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyPSCellInformationIEBindingFieldInject(v *HandoverNotifyPSCellInformationIEBinding) *func(s20.PSCellInformation) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyTAIIEBindingFieldCodec(v *HandoverNotifyTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyTAIIEBindingFieldGet(v *HandoverNotifyTAIIEBinding) *func(*HandoverNotifyIEValue) (*s31.TAI, bool) {
	return &v.get
}
func BridgeHandoverNotifyTAIIEBindingFieldInfo(v *HandoverNotifyTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyTAIIEBindingFieldInject(v *HandoverNotifyTAIIEBinding) *func(s31.TAI) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldCodec(v *HandoverNotifyTunnelInformationIEBinding) *TunnelInformationValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldGet(v *HandoverNotifyTunnelInformationIEBinding) *func(*HandoverNotifyIEValue) (*s34.TunnelInformation, bool) {
	return &v.get
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldInfo(v *HandoverNotifyTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldInject(v *HandoverNotifyTunnelInformationIEBinding) *func(s34.TunnelInformation) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyValueCodecFieldCapture(v *HandoverNotifyValueCodec) *func(HandoverNotify, aper.DecodeState) (HandoverNotify, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverNotifyValueCodecFieldCompare(v *HandoverNotifyValueCodec) *func(HandoverNotify, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverNotifyValueCodecFieldContext(v *HandoverNotifyValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverNotifyValueCodecFieldDecode(v *HandoverNotifyValueCodec) *func([]byte, aper.DecodeState) (HandoverNotify, error) {
	return &v.decode
}
func BridgeHandoverNotifyValueCodecFieldEncode(v *HandoverNotifyValueCodec) *func(HandoverNotify, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverNotifyValueCodecFieldPath(v *HandoverNotifyValueCodec) *aper.Path { return &v.path }
func BridgeHandoverNotifyValueCodecMethodEncodeBudgetValue(v HandoverNotifyValueCodec, a0 HandoverNotify, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverNotifyValueCodecMethodEncodeChanged(v HandoverNotifyValueCodec, a0 HandoverNotify, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageAPERValueFieldContext(v *InitialUEMessageAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageAPERValueFieldReceived(v *InitialUEMessageAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageAPERValueFieldReplay(v *InitialUEMessageAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageAPERValueFieldWithoutReplay(v *InitialUEMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldCodec(v *InitialUEMessageCEModeBSupportIndicatorIEBinding) *s00.CEModeBSupportIndicatorValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldGet(v *InitialUEMessageCEModeBSupportIndicatorIEBinding) *func(*InitialUEMessageIEValue) (*s00.CEModeBSupportIndicator, bool) {
	return &v.get
}
func BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldInfo(v *InitialUEMessageCEModeBSupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldInject(v *InitialUEMessageCEModeBSupportIndicatorIEBinding) *func(s00.CEModeBSupportIndicator) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageCSGIdIEBindingFieldCodec(v *InitialUEMessageCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageCSGIdIEBindingFieldGet(v *InitialUEMessageCSGIdIEBinding) *func(*InitialUEMessageIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgeInitialUEMessageCSGIdIEBindingFieldInfo(v *InitialUEMessageCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageCSGIdIEBindingFieldInject(v *InitialUEMessageCSGIdIEBinding) *func(s00.CSGId) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageCellAccessModeIEBindingFieldCodec(v *InitialUEMessageCellAccessModeIEBinding) *s00.CellAccessModeValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageCellAccessModeIEBindingFieldGet(v *InitialUEMessageCellAccessModeIEBinding) *func(*InitialUEMessageIEValue) (*s00.CellAccessMode, bool) {
	return &v.get
}
func BridgeInitialUEMessageCellAccessModeIEBindingFieldInfo(v *InitialUEMessageCellAccessModeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageCellAccessModeIEBindingFieldInject(v *InitialUEMessageCellAccessModeIEBinding) *func(s00.CellAccessMode) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldCodec(v *InitialUEMessageCoarseUELocationRequestedIEBinding) *s00.CoarseUELocationRequestedValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldGet(v *InitialUEMessageCoarseUELocationRequestedIEBinding) *func(*InitialUEMessageIEValue) (*s00.CoarseUELocationRequested, bool) {
	return &v.get
}
func BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldInfo(v *InitialUEMessageCoarseUELocationRequestedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldInject(v *InitialUEMessageCoarseUELocationRequestedIEBinding) *func(s00.CoarseUELocationRequested) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageCoverageLevelIEBindingFieldCodec(v *InitialUEMessageCoverageLevelIEBinding) *s00.CoverageLevelValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageCoverageLevelIEBindingFieldGet(v *InitialUEMessageCoverageLevelIEBinding) *func(*InitialUEMessageIEValue) (*s00.CoverageLevel, bool) {
	return &v.get
}
func BridgeInitialUEMessageCoverageLevelIEBindingFieldInfo(v *InitialUEMessageCoverageLevelIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageCoverageLevelIEBindingFieldInject(v *InitialUEMessageCoverageLevelIEBinding) *func(s00.CoverageLevel) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageDCNIDIEBindingFieldCodec(v *InitialUEMessageDCNIDIEBinding) *s00.DCNIDValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageDCNIDIEBindingFieldGet(v *InitialUEMessageDCNIDIEBinding) *func(*InitialUEMessageIEValue) (*s00.DCNID, bool) {
	return &v.get
}
func BridgeInitialUEMessageDCNIDIEBindingFieldInfo(v *InitialUEMessageDCNIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageDCNIDIEBindingFieldInject(v *InitialUEMessageDCNIDIEBinding) *func(s00.DCNID) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageEDTSessionIEBindingFieldCodec(v *InitialUEMessageEDTSessionIEBinding) *s00.EDTSessionValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageEDTSessionIEBindingFieldGet(v *InitialUEMessageEDTSessionIEBinding) *func(*InitialUEMessageIEValue) (*s00.EDTSession, bool) {
	return &v.get
}
func BridgeInitialUEMessageEDTSessionIEBindingFieldInfo(v *InitialUEMessageEDTSessionIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageEDTSessionIEBindingFieldInject(v *InitialUEMessageEDTSessionIEBinding) *func(s00.EDTSession) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageENBUES1APIDIEBindingFieldCodec(v *InitialUEMessageENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageENBUES1APIDIEBindingFieldGet(v *InitialUEMessageENBUES1APIDIEBinding) *func(*InitialUEMessageIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeInitialUEMessageENBUES1APIDIEBindingFieldInfo(v *InitialUEMessageENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageENBUES1APIDIEBindingFieldInject(v *InitialUEMessageENBUES1APIDIEBinding) *func(s00.ENBUES1APID) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageEUTRANCGIIEBindingFieldCodec(v *InitialUEMessageEUTRANCGIIEBinding) *s17.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageEUTRANCGIIEBindingFieldGet(v *InitialUEMessageEUTRANCGIIEBinding) *func(*InitialUEMessageIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgeInitialUEMessageEUTRANCGIIEBindingFieldInfo(v *InitialUEMessageEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageEUTRANCGIIEBindingFieldInject(v *InitialUEMessageEUTRANCGIIEBinding) *func(s17.EUTRANCGI) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageFieldExtCount(v *InitialUEMessage) *int64   { return &v.extCount }
func BridgeInitialUEMessageFieldExtData(v *InitialUEMessage) *[][]byte { return &v.extData }
func BridgeInitialUEMessageFieldExtOrigin(v *InitialUEMessage) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInitialUEMessageFieldExtPresent(v *InitialUEMessage) *[]bool       { return &v.extPresent }
func BridgeInitialUEMessageFieldExtWire(v *InitialUEMessage) *[]aper.WireSpan { return &v.extWire }
func BridgeInitialUEMessageFieldPerExtPadding(v *InitialUEMessage) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInitialUEMessageFieldPerPadding(v *InitialUEMessage) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInitialUEMessageFieldProtocolIEsIndef(v *InitialUEMessage) *bool {
	return &v.protocolIEsIndef
}
func BridgeInitialUEMessageFieldReceived(v *InitialUEMessage) *bool { return &v.received }
func BridgeInitialUEMessageFieldReceivedAbsolute(v *InitialUEMessage) *bool {
	return &v.receivedAbsolute
}
func BridgeInitialUEMessageFieldReceivedBytes(v *InitialUEMessage) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInitialUEMessageFieldReceivedLocation(v *InitialUEMessage) *aper.Location {
	return &v.receivedLocation
}
func BridgeInitialUEMessageFieldReplay(v *InitialUEMessage) *aper.Snapshot { return &v.replay }
func BridgeInitialUEMessageFieldStream(v *InitialUEMessage) *aper.WireSpan { return &v.stream }
func BridgeInitialUEMessageFieldWithoutReplay(v *InitialUEMessage) *bool   { return &v.withoutReplay }
func BridgeInitialUEMessageGUMMEIIEBindingFieldCodec(v *InitialUEMessageGUMMEIIEBinding) *s18.GUMMEIValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageGUMMEIIEBindingFieldGet(v *InitialUEMessageGUMMEIIEBinding) *func(*InitialUEMessageIEValue) (*s18.GUMMEI, bool) {
	return &v.get
}
func BridgeInitialUEMessageGUMMEIIEBindingFieldInfo(v *InitialUEMessageGUMMEIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageGUMMEIIEBindingFieldInject(v *InitialUEMessageGUMMEIIEBinding) *func(s18.GUMMEI) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageGUMMEITypeIEBindingFieldCodec(v *InitialUEMessageGUMMEITypeIEBinding) *s00.GUMMEITypeValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageGUMMEITypeIEBindingFieldGet(v *InitialUEMessageGUMMEITypeIEBinding) *func(*InitialUEMessageIEValue) (*s00.GUMMEIType, bool) {
	return &v.get
}
func BridgeInitialUEMessageGUMMEITypeIEBindingFieldInfo(v *InitialUEMessageGUMMEITypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageGUMMEITypeIEBindingFieldInject(v *InitialUEMessageGUMMEITypeIEBinding) *func(s00.GUMMEIType) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageIABNodeIndicationIEBindingFieldCodec(v *InitialUEMessageIABNodeIndicationIEBinding) *s01.IABNodeIndicationValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageIABNodeIndicationIEBindingFieldGet(v *InitialUEMessageIABNodeIndicationIEBinding) *func(*InitialUEMessageIEValue) (*s00.IABNodeIndication, bool) {
	return &v.get
}
func BridgeInitialUEMessageIABNodeIndicationIEBindingFieldInfo(v *InitialUEMessageIABNodeIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageIABNodeIndicationIEBindingFieldInject(v *InitialUEMessageIABNodeIndicationIEBinding) *func(s00.IABNodeIndication) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageIEContainerAPERValueFieldContext(v *InitialUEMessageIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEContainerAPERValueFieldReceived(v *InitialUEMessageIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEContainerAPERValueFieldReplay(v *InitialUEMessageIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEContainerAPERValueFieldWithoutReplay(v *InitialUEMessageIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEContainerValueCodecFieldCapture(v *InitialUEMessageIEContainerValueCodec) *func(InitialUEMessageIEContainer, aper.DecodeState) (InitialUEMessageIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageIEContainerValueCodecFieldCompare(v *InitialUEMessageIEContainerValueCodec) *func(InitialUEMessageIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageIEContainerValueCodecFieldContext(v *InitialUEMessageIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEContainerValueCodecFieldDecode(v *InitialUEMessageIEContainerValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessageIEContainer, error) {
	return &v.decode
}
func BridgeInitialUEMessageIEContainerValueCodecFieldEncode(v *InitialUEMessageIEContainerValueCodec) *func(InitialUEMessageIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageIEContainerValueCodecFieldPath(v *InitialUEMessageIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageIEContainerValueCodecMethodEncodeBudgetValue(v InitialUEMessageIEContainerValueCodec, a0 InitialUEMessageIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageIEContainerValueCodecMethodEncodeChanged(v InitialUEMessageIEContainerValueCodec, a0 InitialUEMessageIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageIEFieldAPERValueFieldContext(v *InitialUEMessageIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEFieldAPERValueFieldReceived(v *InitialUEMessageIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEFieldAPERValueFieldReplay(v *InitialUEMessageIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEFieldAPERValueFieldWithoutReplay(v *InitialUEMessageIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEFieldFieldReceived(v *InitialUEMessageIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeInitialUEMessageIEFieldFieldReplay(v *InitialUEMessageIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEFieldFieldStream(v *InitialUEMessageIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialUEMessageIEFieldFieldWithoutReplay(v *InitialUEMessageIEField) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEFieldMethodMarshalAPERTo(v *InitialUEMessageIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(v *InitialUEMessageIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialUEMessageIEFieldValueCodecFieldCapture(v *InitialUEMessageIEFieldValueCodec) *func(InitialUEMessageIEField, aper.DecodeState) (InitialUEMessageIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageIEFieldValueCodecFieldCompare(v *InitialUEMessageIEFieldValueCodec) *func(InitialUEMessageIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageIEFieldValueCodecFieldContext(v *InitialUEMessageIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEFieldValueCodecFieldDecode(v *InitialUEMessageIEFieldValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessageIEField, error) {
	return &v.decode
}
func BridgeInitialUEMessageIEFieldValueCodecFieldEncode(v *InitialUEMessageIEFieldValueCodec) *func(InitialUEMessageIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageIEFieldValueCodecFieldPath(v *InitialUEMessageIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageIEFieldValueCodecMethodEncodeBudgetValue(v InitialUEMessageIEFieldValueCodec, a0 InitialUEMessageIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageIEFieldValueCodecMethodEncodeChanged(v InitialUEMessageIEFieldValueCodec, a0 InitialUEMessageIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageIETableMethodInfoCEModeBSupportIndicator(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoCEModeBSupportIndicator()
}
func BridgeInitialUEMessageIETableMethodInfoCSGId(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoCSGId()
}
func BridgeInitialUEMessageIETableMethodInfoCellAccessMode(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoCellAccessMode()
}
func BridgeInitialUEMessageIETableMethodInfoCoarseUELocationRequested(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoCoarseUELocationRequested()
}
func BridgeInitialUEMessageIETableMethodInfoCoverageLevel(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoCoverageLevel()
}
func BridgeInitialUEMessageIETableMethodInfoDCNID(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoDCNID()
}
func BridgeInitialUEMessageIETableMethodInfoEDTSession(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoEDTSession()
}
func BridgeInitialUEMessageIETableMethodInfoENBUES1APID(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeInitialUEMessageIETableMethodInfoEUTRANCGI(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoEUTRANCGI()
}
func BridgeInitialUEMessageIETableMethodInfoGUMMEIID(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoGUMMEIID()
}
func BridgeInitialUEMessageIETableMethodInfoGUMMEIType(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoGUMMEIType()
}
func BridgeInitialUEMessageIETableMethodInfoGWTransportLayerAddress(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoGWTransportLayerAddress()
}
func BridgeInitialUEMessageIETableMethodInfoIABNodeIndication(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoIABNodeIndication()
}
func BridgeInitialUEMessageIETableMethodInfoLHNID(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoLHNID()
}
func BridgeInitialUEMessageIETableMethodInfoLTENTNTAIInformation(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgeInitialUEMessageIETableMethodInfoMMEGroupID(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoMMEGroupID()
}
func BridgeInitialUEMessageIETableMethodInfoNASPDU(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoNASPDU()
}
func BridgeInitialUEMessageIETableMethodInfoRRCEstablishmentCause(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoRRCEstablishmentCause()
}
func BridgeInitialUEMessageIETableMethodInfoRelayNodeIndicator(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoRelayNodeIndicator()
}
func BridgeInitialUEMessageIETableMethodInfoSIPTOLGWTransportLayerAddress(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoSIPTOLGWTransportLayerAddress()
}
func BridgeInitialUEMessageIETableMethodInfoSTMSI(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeInitialUEMessageIETableMethodInfoTAI(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoTAI()
}
func BridgeInitialUEMessageIETableMethodInfoTunnelInformationForBBF(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoTunnelInformationForBBF()
}
func BridgeInitialUEMessageIETableMethodInfoUEApplicationLayerMeasurementCapability(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoUEApplicationLayerMeasurementCapability()
}
func BridgeInitialUEMessageIETableMethodInfoUEUsageType(v InitialUEMessageIETable) s00.FieldInfo {
	return v.infoUEUsageType()
}
func BridgeInitialUEMessageIEValueERABIEContainerListAPERValueFieldContext(v *InitialUEMessageIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueERABIEContainerListAPERValueFieldReceived(v *InitialUEMessageIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEValueERABIEContainerListAPERValueFieldReplay(v *InitialUEMessageIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *InitialUEMessageIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldCapture(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *func(InitialUEMessageIEValueERABIEContainerList, aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldCompare(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *func(InitialUEMessageIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldContext(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldDecode(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessageIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldEncode(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *func(InitialUEMessageIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldPath(v *InitialUEMessageIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v InitialUEMessageIEValueERABIEContainerListValueCodec, a0 InitialUEMessageIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageIEValueERABIEContainerListValueCodecMethodEncodeChanged(v InitialUEMessageIEValueERABIEContainerListValueCodec, a0 InitialUEMessageIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageIEValueFieldId(v *InitialUEMessageIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeInitialUEMessageIEValueFieldIsOpaque(v *InitialUEMessageIEValue) *bool       { return &v.isOpaque }
func BridgeInitialUEMessageIEValueFieldOpaque(v *InitialUEMessageIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInitialUEMessageIEValueFieldReceived(v *InitialUEMessageIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEValueFieldReplay(v *InitialUEMessageIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEValueFieldRowCEModeBSupportIndicator(v *InitialUEMessageIEValue) **s00.CEModeBSupportIndicator {
	return &v.rowCEModeBSupportIndicator
}
func BridgeInitialUEMessageIEValueFieldRowCSGId(v *InitialUEMessageIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgeInitialUEMessageIEValueFieldRowCellAccessMode(v *InitialUEMessageIEValue) **s00.CellAccessMode {
	return &v.rowCellAccessMode
}
func BridgeInitialUEMessageIEValueFieldRowCoarseUELocationRequested(v *InitialUEMessageIEValue) **s00.CoarseUELocationRequested {
	return &v.rowCoarseUELocationRequested
}
func BridgeInitialUEMessageIEValueFieldRowCoverageLevel(v *InitialUEMessageIEValue) **s00.CoverageLevel {
	return &v.rowCoverageLevel
}
func BridgeInitialUEMessageIEValueFieldRowDCNID(v *InitialUEMessageIEValue) **s00.DCNID {
	return &v.rowDCNID
}
func BridgeInitialUEMessageIEValueFieldRowEDTSession(v *InitialUEMessageIEValue) **s00.EDTSession {
	return &v.rowEDTSession
}
func BridgeInitialUEMessageIEValueFieldRowENBUES1APID(v *InitialUEMessageIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeInitialUEMessageIEValueFieldRowEUTRANCGI(v *InitialUEMessageIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeInitialUEMessageIEValueFieldRowGUMMEIID(v *InitialUEMessageIEValue) **s18.GUMMEI {
	return &v.rowGUMMEIID
}
func BridgeInitialUEMessageIEValueFieldRowGUMMEIType(v *InitialUEMessageIEValue) **s00.GUMMEIType {
	return &v.rowGUMMEIType
}
func BridgeInitialUEMessageIEValueFieldRowGWTransportLayerAddress(v *InitialUEMessageIEValue) **s00.TransportLayerAddress {
	return &v.rowGWTransportLayerAddress
}
func BridgeInitialUEMessageIEValueFieldRowIABNodeIndication(v *InitialUEMessageIEValue) **s00.IABNodeIndication {
	return &v.rowIABNodeIndication
}
func BridgeInitialUEMessageIEValueFieldRowLHNID(v *InitialUEMessageIEValue) **s00.LHNID {
	return &v.rowLHNID
}
func BridgeInitialUEMessageIEValueFieldRowLTENTNTAIInformation(v *InitialUEMessageIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeInitialUEMessageIEValueFieldRowMMEGroupID(v *InitialUEMessageIEValue) **s00.MMEGroupID {
	return &v.rowMMEGroupID
}
func BridgeInitialUEMessageIEValueFieldRowNASPDU(v *InitialUEMessageIEValue) **s00.NASPDU {
	return &v.rowNASPDU
}
func BridgeInitialUEMessageIEValueFieldRowRRCEstablishmentCause(v *InitialUEMessageIEValue) **s00.RRCEstablishmentCause {
	return &v.rowRRCEstablishmentCause
}
func BridgeInitialUEMessageIEValueFieldRowRelayNodeIndicator(v *InitialUEMessageIEValue) **s00.RelayNodeIndicator {
	return &v.rowRelayNodeIndicator
}
func BridgeInitialUEMessageIEValueFieldRowSIPTOLGWTransportLayerAddress(v *InitialUEMessageIEValue) **s00.TransportLayerAddress {
	return &v.rowSIPTOLGWTransportLayerAddress
}
func BridgeInitialUEMessageIEValueFieldRowSTMSI(v *InitialUEMessageIEValue) **s27.STMSI {
	return &v.rowSTMSI
}
func BridgeInitialUEMessageIEValueFieldRowTAI(v *InitialUEMessageIEValue) **s31.TAI { return &v.rowTAI }
func BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(v *InitialUEMessageIEValue) **s34.TunnelInformation {
	return &v.rowTunnelInformationForBBF
}
func BridgeInitialUEMessageIEValueFieldRowUEApplicationLayerMeasurementCapability(v *InitialUEMessageIEValue) **s00.UEApplicationLayerMeasurementCapability {
	return &v.rowUEApplicationLayerMeasurementCapability
}
func BridgeInitialUEMessageIEValueFieldRowUEUsageType(v *InitialUEMessageIEValue) **s00.UEUsageType {
	return &v.rowUEUsageType
}
func BridgeInitialUEMessageIEValueMethodCaptureSemantics(v InitialUEMessageIEValue, a0 aper.SemanticCapture) InitialUEMessageIEValue {
	return v.captureSemantics(a0)
}
func BridgeInitialUEMessageIEValueMethodCompareSemantics(v InitialUEMessageIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitialUEMessageIEValueMethodDecode(v InitialUEMessageIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InitialUEMessageIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInitialUEMessageIEValueMethodEncode(v InitialUEMessageIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInitialUEMessageIEValueMethodEncodeFresh(v InitialUEMessageIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInitialUEMessageIEValueMethodMatchesID(v InitialUEMessageIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeInitialUEMessageIEValueMethodReason(v InitialUEMessageIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInitialUEMessageIEValueMethodRule(v InitialUEMessageIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessageIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec, a0 InitialUEMessageIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec, a0 InitialUEMessageIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListAPERValueFieldContext(v *InitialUEMessageIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListAPERValueFieldReceived(v *InitialUEMessageIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListAPERValueFieldReplay(v *InitialUEMessageIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *InitialUEMessageIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldCapture(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolIEContainerList, aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldCompare(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldContext(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldDecode(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessageIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldEncode(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *func(InitialUEMessageIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldPath(v *InitialUEMessageIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v InitialUEMessageIEValueProtocolIEContainerListValueCodec, a0 InitialUEMessageIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v InitialUEMessageIEValueProtocolIEContainerListValueCodec, a0 InitialUEMessageIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialUEMessageLHNIDIEBindingFieldCodec(v *InitialUEMessageLHNIDIEBinding) *s01.LHNIDValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageLHNIDIEBindingFieldGet(v *InitialUEMessageLHNIDIEBinding) *func(*InitialUEMessageIEValue) (*s00.LHNID, bool) {
	return &v.get
}
func BridgeInitialUEMessageLHNIDIEBindingFieldInfo(v *InitialUEMessageLHNIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageLHNIDIEBindingFieldInject(v *InitialUEMessageLHNIDIEBinding) *func(s00.LHNID) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldCodec(v *InitialUEMessageLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldGet(v *InitialUEMessageLTENTNTAIInformationIEBinding) *func(*InitialUEMessageIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldInfo(v *InitialUEMessageLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldInject(v *InitialUEMessageLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageMMEGroupIDIEBindingFieldCodec(v *InitialUEMessageMMEGroupIDIEBinding) *s01.MMEGroupIDValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageMMEGroupIDIEBindingFieldGet(v *InitialUEMessageMMEGroupIDIEBinding) *func(*InitialUEMessageIEValue) (*s00.MMEGroupID, bool) {
	return &v.get
}
func BridgeInitialUEMessageMMEGroupIDIEBindingFieldInfo(v *InitialUEMessageMMEGroupIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageMMEGroupIDIEBindingFieldInject(v *InitialUEMessageMMEGroupIDIEBinding) *func(s00.MMEGroupID) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageMethodMarshalAPERBudget(v *InitialUEMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitialUEMessageMethodMarshalAPERBudgetValue(v *InitialUEMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInitialUEMessageMethodMarshalAPERChanged(v *InitialUEMessage, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInitialUEMessageMethodMarshalAPERChangedValue(v *InitialUEMessage, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInitialUEMessageMethodMarshalAPERLegacy(v *InitialUEMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInitialUEMessageMethodMarshalAPERNewValue(v *InitialUEMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInitialUEMessageMethodMarshalAPERPlanned(v *InitialUEMessage, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInitialUEMessageMethodMarshalAPERTo(v *InitialUEMessage, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialUEMessageMethodUnmarshalAPERFrom(v *InitialUEMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialUEMessageMethodUnmarshalAPERLegacy(v *InitialUEMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInitialUEMessageMethodUnmarshalAPERWithOptions(v *InitialUEMessage, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitialUEMessageNASPDUIEBindingFieldCodec(v *InitialUEMessageNASPDUIEBinding) *s01.NASPDUValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageNASPDUIEBindingFieldGet(v *InitialUEMessageNASPDUIEBinding) *func(*InitialUEMessageIEValue) (*s00.NASPDU, bool) {
	return &v.get
}
func BridgeInitialUEMessageNASPDUIEBindingFieldInfo(v *InitialUEMessageNASPDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageNASPDUIEBindingFieldInject(v *InitialUEMessageNASPDUIEBinding) *func(s00.NASPDU) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldCodec(v *InitialUEMessageRRCEstablishmentCauseIEBinding) *s01.RRCEstablishmentCauseValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldGet(v *InitialUEMessageRRCEstablishmentCauseIEBinding) *func(*InitialUEMessageIEValue) (*s00.RRCEstablishmentCause, bool) {
	return &v.get
}
func BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldInfo(v *InitialUEMessageRRCEstablishmentCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldInject(v *InitialUEMessageRRCEstablishmentCauseIEBinding) *func(s00.RRCEstablishmentCause) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldCodec(v *InitialUEMessageRelayNodeIndicatorIEBinding) *s01.RelayNodeIndicatorValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldGet(v *InitialUEMessageRelayNodeIndicatorIEBinding) *func(*InitialUEMessageIEValue) (*s00.RelayNodeIndicator, bool) {
	return &v.get
}
func BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldInfo(v *InitialUEMessageRelayNodeIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldInject(v *InitialUEMessageRelayNodeIndicatorIEBinding) *func(s00.RelayNodeIndicator) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageSTMSIIEBindingFieldCodec(v *InitialUEMessageSTMSIIEBinding) *s28.STMSIValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageSTMSIIEBindingFieldGet(v *InitialUEMessageSTMSIIEBinding) *func(*InitialUEMessageIEValue) (*s27.STMSI, bool) {
	return &v.get
}
func BridgeInitialUEMessageSTMSIIEBindingFieldInfo(v *InitialUEMessageSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageSTMSIIEBindingFieldInject(v *InitialUEMessageSTMSIIEBinding) *func(s27.STMSI) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageTAIIEBindingFieldCodec(v *InitialUEMessageTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageTAIIEBindingFieldGet(v *InitialUEMessageTAIIEBinding) *func(*InitialUEMessageIEValue) (*s31.TAI, bool) {
	return &v.get
}
func BridgeInitialUEMessageTAIIEBindingFieldInfo(v *InitialUEMessageTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageTAIIEBindingFieldInject(v *InitialUEMessageTAIIEBinding) *func(s31.TAI) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageTransportLayerAddressIEBindingFieldCodec(v *InitialUEMessageTransportLayerAddressIEBinding) *s02.TransportLayerAddressValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageTransportLayerAddressIEBindingFieldGet(v *InitialUEMessageTransportLayerAddressIEBinding) *func(*InitialUEMessageIEValue) (*s00.TransportLayerAddress, bool) {
	return &v.get
}
func BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInfo(v *InitialUEMessageTransportLayerAddressIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInject(v *InitialUEMessageTransportLayerAddressIEBinding) *func(s00.TransportLayerAddress) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldCodec(v *InitialUEMessageTunnelInformationIEBinding) *TunnelInformationValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldGet(v *InitialUEMessageTunnelInformationIEBinding) *func(*InitialUEMessageIEValue) (*s34.TunnelInformation, bool) {
	return &v.get
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldInfo(v *InitialUEMessageTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldInject(v *InitialUEMessageTunnelInformationIEBinding) *func(s34.TunnelInformation) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldCodec(v *InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) *s02.UEApplicationLayerMeasurementCapabilityValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldGet(v *InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) *func(*InitialUEMessageIEValue) (*s00.UEApplicationLayerMeasurementCapability, bool) {
	return &v.get
}
func BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldInfo(v *InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldInject(v *InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding) *func(s00.UEApplicationLayerMeasurementCapability) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageUEUsageTypeIEBindingFieldCodec(v *InitialUEMessageUEUsageTypeIEBinding) *s02.UEUsageTypeValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageUEUsageTypeIEBindingFieldGet(v *InitialUEMessageUEUsageTypeIEBinding) *func(*InitialUEMessageIEValue) (*s00.UEUsageType, bool) {
	return &v.get
}
func BridgeInitialUEMessageUEUsageTypeIEBindingFieldInfo(v *InitialUEMessageUEUsageTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageUEUsageTypeIEBindingFieldInject(v *InitialUEMessageUEUsageTypeIEBinding) *func(s00.UEUsageType) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageValueCodecFieldCapture(v *InitialUEMessageValueCodec) *func(InitialUEMessage, aper.DecodeState) (InitialUEMessage, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialUEMessageValueCodecFieldCompare(v *InitialUEMessageValueCodec) *func(InitialUEMessage, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialUEMessageValueCodecFieldContext(v *InitialUEMessageValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialUEMessageValueCodecFieldDecode(v *InitialUEMessageValueCodec) *func([]byte, aper.DecodeState) (InitialUEMessage, error) {
	return &v.decode
}
func BridgeInitialUEMessageValueCodecFieldEncode(v *InitialUEMessageValueCodec) *func(InitialUEMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialUEMessageValueCodecFieldPath(v *InitialUEMessageValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialUEMessageValueCodecMethodEncodeBudgetValue(v InitialUEMessageValueCodec, a0 InitialUEMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialUEMessageValueCodecMethodEncodeChanged(v InitialUEMessageValueCodec, a0 InitialUEMessage, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetTypeFieldPerOpenTypePadding(v *ResetType) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeResetTypeFieldPerPadding(v *ResetType) *aper.CompletePadding { return &v.perPadding }
func BridgeResetTypeFieldReceived(v *ResetType) *bool                   { return &v.received }
func BridgeResetTypeFieldReceivedAbsolute(v *ResetType) *bool           { return &v.receivedAbsolute }
func BridgeResetTypeFieldReceivedBytes(v *ResetType) *aper.WireSpan     { return &v.receivedBytes }
func BridgeResetTypeFieldReceivedLocation(v *ResetType) *aper.Location  { return &v.receivedLocation }
func BridgeResetTypeFieldReplay(v *ResetType) *aper.Snapshot            { return &v.replay }
func BridgeResetTypeFieldStream(v *ResetType) *aper.WireSpan            { return &v.stream }
func BridgeResetTypeFieldWithoutReplay(v *ResetType) *bool              { return &v.withoutReplay }
func BridgeResetTypeMethodMarshalAPERBudget(v *ResetType, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResetTypeMethodMarshalAPERBudgetValue(v *ResetType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeResetTypeMethodMarshalAPERChanged(v *ResetType, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResetTypeMethodMarshalAPERChangedValue(v *ResetType, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResetTypeMethodMarshalAPERLegacy(v *ResetType) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResetTypeMethodMarshalAPERNewValue(v *ResetType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeResetTypeMethodMarshalAPERPlanned(v *ResetType, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeResetTypeMethodMarshalAPERTo(v *ResetType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetTypeMethodUnmarshalAPERFrom(v *ResetType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetTypeMethodUnmarshalAPERLegacy(v *ResetType, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResetTypeMethodUnmarshalAPERWithOptions(v *ResetType, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTunnelInformationAPERValueFieldContext(v *TunnelInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTunnelInformationAPERValueFieldReceived(v *TunnelInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTunnelInformationAPERValueFieldReplay(v *TunnelInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTunnelInformationAPERValueFieldWithoutReplay(v *TunnelInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTunnelInformationValueCodecFieldCapture(v *TunnelInformationValueCodec) *func(s34.TunnelInformation, aper.DecodeState) (s34.TunnelInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeTunnelInformationValueCodecFieldCompare(v *TunnelInformationValueCodec) *func(s34.TunnelInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTunnelInformationValueCodecFieldContext(v *TunnelInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTunnelInformationValueCodecFieldDecode(v *TunnelInformationValueCodec) *func([]byte, aper.DecodeState) (s34.TunnelInformation, error) {
	return &v.decode
}
func BridgeTunnelInformationValueCodecFieldEncode(v *TunnelInformationValueCodec) *func(s34.TunnelInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTunnelInformationValueCodecFieldPath(v *TunnelInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTunnelInformationValueCodecMethodEncodeBudgetValue(v TunnelInformationValueCodec, a0 s34.TunnelInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTunnelInformationValueCodecMethodEncodeChanged(v TunnelInformationValueCodec, a0 s34.TunnelInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAggregateMaximumBitrateAPERValueFieldContext(v *UEAggregateMaximumBitrateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAggregateMaximumBitrateAPERValueFieldReceived(v *UEAggregateMaximumBitrateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAggregateMaximumBitrateAPERValueFieldReplay(v *UEAggregateMaximumBitrateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAggregateMaximumBitrateAPERValueFieldWithoutReplay(v *UEAggregateMaximumBitrateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAggregateMaximumBitrateFieldExtCount(v *UEAggregateMaximumBitrate) *int64 {
	return &v.extCount
}
func BridgeUEAggregateMaximumBitrateFieldExtData(v *UEAggregateMaximumBitrate) *[][]byte {
	return &v.extData
}
func BridgeUEAggregateMaximumBitrateFieldExtOrigin(v *UEAggregateMaximumBitrate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEAggregateMaximumBitrateFieldExtPresent(v *UEAggregateMaximumBitrate) *[]bool {
	return &v.extPresent
}
func BridgeUEAggregateMaximumBitrateFieldExtWire(v *UEAggregateMaximumBitrate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEAggregateMaximumBitrateFieldIEExtensionsIndef(v *UEAggregateMaximumBitrate) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUEAggregateMaximumBitrateFieldPerExtPadding(v *UEAggregateMaximumBitrate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEAggregateMaximumBitrateFieldPerPadding(v *UEAggregateMaximumBitrate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEAggregateMaximumBitrateFieldReceived(v *UEAggregateMaximumBitrate) *bool {
	return &v.received
}
func BridgeUEAggregateMaximumBitrateFieldReceivedAbsolute(v *UEAggregateMaximumBitrate) *bool {
	return &v.receivedAbsolute
}
func BridgeUEAggregateMaximumBitrateFieldReceivedBytes(v *UEAggregateMaximumBitrate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEAggregateMaximumBitrateFieldReceivedLocation(v *UEAggregateMaximumBitrate) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEAggregateMaximumBitrateFieldReplay(v *UEAggregateMaximumBitrate) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAggregateMaximumBitrateFieldStream(v *UEAggregateMaximumBitrate) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAggregateMaximumBitrateFieldWithoutReplay(v *UEAggregateMaximumBitrate) *bool {
	return &v.withoutReplay
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v *UEAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudgetValue(v *UEAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERChanged(v *UEAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERChangedValue(v *UEAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERLegacy(v *UEAggregateMaximumBitrate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERNewValue(v *UEAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERPlanned(v *UEAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEAggregateMaximumBitrateMethodMarshalAPERTo(v *UEAggregateMaximumBitrate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(v *UEAggregateMaximumBitrate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERLegacy(v *UEAggregateMaximumBitrate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERWithOptions(v *UEAggregateMaximumBitrate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(v *UEAggregateMaximumBitrateValueCodec) *func(UEAggregateMaximumBitrate, aper.DecodeState) (UEAggregateMaximumBitrate, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(v *UEAggregateMaximumBitrateValueCodec) *func(UEAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldContext(v *UEAggregateMaximumBitrateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(v *UEAggregateMaximumBitrateValueCodec) *func([]byte, aper.DecodeState) (UEAggregateMaximumBitrate, error) {
	return &v.decode
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(v *UEAggregateMaximumBitrateValueCodec) *func(UEAggregateMaximumBitrate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAggregateMaximumBitrateValueCodecFieldPath(v *UEAggregateMaximumBitrateValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAggregateMaximumBitrateValueCodecMethodEncodeBudgetValue(v UEAggregateMaximumBitrateValueCodec, a0 UEAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAggregateMaximumBitrateValueCodecMethodEncodeChanged(v UEAggregateMaximumBitrateValueCodec, a0 UEAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAppLayerMeasConfigAPERValueFieldContext(v *UEAppLayerMeasConfigAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAppLayerMeasConfigAPERValueFieldReceived(v *UEAppLayerMeasConfigAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAppLayerMeasConfigAPERValueFieldReplay(v *UEAppLayerMeasConfigAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAppLayerMeasConfigAPERValueFieldWithoutReplay(v *UEAppLayerMeasConfigAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAppLayerMeasConfigFieldExtCount(v *UEAppLayerMeasConfig) *int64   { return &v.extCount }
func BridgeUEAppLayerMeasConfigFieldExtData(v *UEAppLayerMeasConfig) *[][]byte { return &v.extData }
func BridgeUEAppLayerMeasConfigFieldExtOrigin(v *UEAppLayerMeasConfig) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEAppLayerMeasConfigFieldExtPresent(v *UEAppLayerMeasConfig) *[]bool { return &v.extPresent }
func BridgeUEAppLayerMeasConfigFieldExtWire(v *UEAppLayerMeasConfig) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEAppLayerMeasConfigFieldIEExtensionsIndef(v *UEAppLayerMeasConfig) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUEAppLayerMeasConfigFieldPerExtPadding(v *UEAppLayerMeasConfig) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEAppLayerMeasConfigFieldPerPadding(v *UEAppLayerMeasConfig) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEAppLayerMeasConfigFieldReceived(v *UEAppLayerMeasConfig) *bool { return &v.received }
func BridgeUEAppLayerMeasConfigFieldReceivedAbsolute(v *UEAppLayerMeasConfig) *bool {
	return &v.receivedAbsolute
}
func BridgeUEAppLayerMeasConfigFieldReceivedBytes(v *UEAppLayerMeasConfig) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEAppLayerMeasConfigFieldReceivedLocation(v *UEAppLayerMeasConfig) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEAppLayerMeasConfigFieldReplay(v *UEAppLayerMeasConfig) *aper.Snapshot { return &v.replay }
func BridgeUEAppLayerMeasConfigFieldStream(v *UEAppLayerMeasConfig) *aper.WireSpan { return &v.stream }
func BridgeUEAppLayerMeasConfigFieldWithoutReplay(v *UEAppLayerMeasConfig) *bool {
	return &v.withoutReplay
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERBudget(v *UEAppLayerMeasConfig, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERBudgetValue(v *UEAppLayerMeasConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERChanged(v *UEAppLayerMeasConfig, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERChangedValue(v *UEAppLayerMeasConfig, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERLegacy(v *UEAppLayerMeasConfig) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERNewValue(v *UEAppLayerMeasConfig, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERPlanned(v *UEAppLayerMeasConfig, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEAppLayerMeasConfigMethodMarshalAPERTo(v *UEAppLayerMeasConfig, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEAppLayerMeasConfigMethodUnmarshalAPERFrom(v *UEAppLayerMeasConfig, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEAppLayerMeasConfigMethodUnmarshalAPERLegacy(v *UEAppLayerMeasConfig, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEAppLayerMeasConfigMethodUnmarshalAPERWithOptions(v *UEAppLayerMeasConfig, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEAppLayerMeasConfigValueCodecFieldCapture(v *UEAppLayerMeasConfigValueCodec) *func(UEAppLayerMeasConfig, aper.DecodeState) (UEAppLayerMeasConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAppLayerMeasConfigValueCodecFieldCompare(v *UEAppLayerMeasConfigValueCodec) *func(UEAppLayerMeasConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAppLayerMeasConfigValueCodecFieldContext(v *UEAppLayerMeasConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAppLayerMeasConfigValueCodecFieldDecode(v *UEAppLayerMeasConfigValueCodec) *func([]byte, aper.DecodeState) (UEAppLayerMeasConfig, error) {
	return &v.decode
}
func BridgeUEAppLayerMeasConfigValueCodecFieldEncode(v *UEAppLayerMeasConfigValueCodec) *func(UEAppLayerMeasConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAppLayerMeasConfigValueCodecFieldPath(v *UEAppLayerMeasConfigValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAppLayerMeasConfigValueCodecMethodEncodeBudgetValue(v UEAppLayerMeasConfigValueCodec, a0 UEAppLayerMeasConfig, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAppLayerMeasConfigValueCodecMethodEncodeChanged(v UEAppLayerMeasConfigValueCodec, a0 UEAppLayerMeasConfig, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldExtCount(v *UEAssociatedLogicalS1ConnectionItem) *int64 {
	return &v.extCount
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldExtData(v *UEAssociatedLogicalS1ConnectionItem) *[][]byte {
	return &v.extData
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldExtOrigin(v *UEAssociatedLogicalS1ConnectionItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldExtPresent(v *UEAssociatedLogicalS1ConnectionItem) *[]bool {
	return &v.extPresent
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldExtWire(v *UEAssociatedLogicalS1ConnectionItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldIEExtensionsIndef(v *UEAssociatedLogicalS1ConnectionItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldPerExtPadding(v *UEAssociatedLogicalS1ConnectionItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldPerPadding(v *UEAssociatedLogicalS1ConnectionItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldReceived(v *UEAssociatedLogicalS1ConnectionItem) *bool {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldReceivedAbsolute(v *UEAssociatedLogicalS1ConnectionItem) *bool {
	return &v.receivedAbsolute
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldReceivedBytes(v *UEAssociatedLogicalS1ConnectionItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldReceivedLocation(v *UEAssociatedLogicalS1ConnectionItem) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldReplay(v *UEAssociatedLogicalS1ConnectionItem) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldStream(v *UEAssociatedLogicalS1ConnectionItem) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAssociatedLogicalS1ConnectionItemFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItem) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERBudget(v *UEAssociatedLogicalS1ConnectionItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERBudgetValue(v *UEAssociatedLogicalS1ConnectionItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERChanged(v *UEAssociatedLogicalS1ConnectionItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERChangedValue(v *UEAssociatedLogicalS1ConnectionItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERNewValue(v *UEAssociatedLogicalS1ConnectionItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERPlanned(v *UEAssociatedLogicalS1ConnectionItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodMarshalAPERTo(v *UEAssociatedLogicalS1ConnectionItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodUnmarshalAPERFrom(v *UEAssociatedLogicalS1ConnectionItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodUnmarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemMethodUnmarshalAPERWithOptions(v *UEAssociatedLogicalS1ConnectionItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEContainer, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldFieldStream(v *UEAssociatedLogicalS1ConnectionItemResAckIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldMethodMarshalAPERTo(v *UEAssociatedLogicalS1ConnectionItemResAckIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldMethodUnmarshalAPERFrom(v *UEAssociatedLogicalS1ConnectionItemResAckIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEField, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldId(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldIsOpaque(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldOpaque(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) **UEAssociatedLogicalS1ConnectionItem {
	return &v.rowUEAssociatedLogicalS1ConnectionItem
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodCaptureSemantics(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResAckIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodCompareSemantics(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodDecode(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResAckIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodEncode(v UEAssociatedLogicalS1ConnectionItemResAckIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodEncodeFresh(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodMatchesID(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodReason(v UEAssociatedLogicalS1ConnectionItemResAckIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueMethodRule(v UEAssociatedLogicalS1ConnectionItemResAckIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckTableMethodInfoUEAssociatedLogicalS1ConnectionItem(v UEAssociatedLogicalS1ConnectionItemResAckTable) s00.FieldInfo {
	return v.infoUEAssociatedLogicalS1ConnectionItem()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBindingFieldCodec(v *UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) *UEAssociatedLogicalS1ConnectionItemValueCodec {
	return &v.codec
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBindingFieldGet(v *UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) *func(*UEAssociatedLogicalS1ConnectionItemResAckIEValue) (*UEAssociatedLogicalS1ConnectionItem, bool) {
	return &v.get
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBindingFieldInfo(v *UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBindingFieldInject(v *UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding) *func(UEAssociatedLogicalS1ConnectionItem) UEAssociatedLogicalS1ConnectionItemResAckIEValue {
	return &v.inject
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEContainer, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldFieldStream(v *UEAssociatedLogicalS1ConnectionItemResIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldMethodMarshalAPERTo(v *UEAssociatedLogicalS1ConnectionItemResIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldMethodUnmarshalAPERFrom(v *UEAssociatedLogicalS1ConnectionItemResIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEField, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEField, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldId(v *UEAssociatedLogicalS1ConnectionItemResIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldIsOpaque(v *UEAssociatedLogicalS1ConnectionItemResIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldOpaque(v *UEAssociatedLogicalS1ConnectionItemResIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueFieldRowUEAssociatedLogicalS1ConnectionItem(v *UEAssociatedLogicalS1ConnectionItemResIEValue) **UEAssociatedLogicalS1ConnectionItem {
	return &v.rowUEAssociatedLogicalS1ConnectionItem
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodCaptureSemantics(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodCompareSemantics(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodDecode(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodEncode(v UEAssociatedLogicalS1ConnectionItemResIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodEncodeFresh(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodMatchesID(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodReason(v UEAssociatedLogicalS1ConnectionItemResIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodRule(v UEAssociatedLogicalS1ConnectionItemResIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *func(UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec, a0 UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResTableMethodInfoUEAssociatedLogicalS1ConnectionItem(v UEAssociatedLogicalS1ConnectionItemResTable) s00.FieldInfo {
	return v.infoUEAssociatedLogicalS1ConnectionItem()
}
func BridgeUEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBindingFieldCodec(v *UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) *UEAssociatedLogicalS1ConnectionItemValueCodec {
	return &v.codec
}
func BridgeUEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBindingFieldGet(v *UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) *func(*UEAssociatedLogicalS1ConnectionItemResIEValue) (*UEAssociatedLogicalS1ConnectionItem, bool) {
	return &v.get
}
func BridgeUEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBindingFieldInfo(v *UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBindingFieldInject(v *UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding) *func(UEAssociatedLogicalS1ConnectionItem) UEAssociatedLogicalS1ConnectionItemResIEValue {
	return &v.inject
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *func(UEAssociatedLogicalS1ConnectionItem, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *func(UEAssociatedLogicalS1ConnectionItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *func(UEAssociatedLogicalS1ConnectionItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionItemValueCodec, a0 UEAssociatedLogicalS1ConnectionItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionItemValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionItemValueCodec, a0 UEAssociatedLogicalS1ConnectionItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionListResAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionListResAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionListResAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionListResAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionListResAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionListResAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckAPERValueFieldContext(v *UEAssociatedLogicalS1ConnectionListResAckAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckAPERValueFieldReceived(v *UEAssociatedLogicalS1ConnectionListResAckAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckAPERValueFieldReplay(v *UEAssociatedLogicalS1ConnectionListResAckAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckAPERValueFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionListResAckAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *func(UEAssociatedLogicalS1ConnectionListResAck, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *func(UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListResAck, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *func(UEAssociatedLogicalS1ConnectionListResAck, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionListResAckValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionListResAckValueCodec, a0 UEAssociatedLogicalS1ConnectionListResAck, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionListResAckValueCodec, a0 UEAssociatedLogicalS1ConnectionListResAck, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCapture(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *func(UEAssociatedLogicalS1ConnectionListRes, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot) {
	return &v.capture
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCompare(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *func(UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldContext(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldDecode(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *func([]byte, aper.DecodeState) (UEAssociatedLogicalS1ConnectionListRes, error) {
	return &v.decode
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldEncode(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *func(UEAssociatedLogicalS1ConnectionListRes, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldPath(v *UEAssociatedLogicalS1ConnectionListResValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecMethodEncodeBudgetValue(v UEAssociatedLogicalS1ConnectionListResValueCodec, a0 UEAssociatedLogicalS1ConnectionListRes, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResValueCodecMethodEncodeChanged(v UEAssociatedLogicalS1ConnectionListResValueCodec, a0 UEAssociatedLogicalS1ConnectionListRes, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
