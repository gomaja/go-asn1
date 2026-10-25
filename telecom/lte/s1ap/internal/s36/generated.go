// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s36 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s36

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
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ResetIEContainer is ProtocolIE-Container {{ResetIEs}} of TS 36.413: a list of ResetIEField values.
type ResetIEContainer []ResetIEField

// ResetIEField is ProtocolIE-Field {{ResetIEs}} of TS 36.413: an information element field.
type ResetIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ResetIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEField) WithoutReplay() ResetIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ResetIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ResetIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ResetIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetIEField{}
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
	var zero ResetIEValue

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
func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainer(v *s35.HandoverNotifyIEContainer, s *aper.SemanticCapture) {
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
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainer(v *s35.HandoverNotifyIEContainer, s *aper.SemanticComparison) {
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
func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainer(v *s35.InitialUEMessageIEContainer, s *aper.SemanticCapture) {
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
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainer(v *s35.InitialUEMessageIEContainer, s *aper.SemanticComparison) {
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
func BridgeResetIEValueCaptureS1APProtocolIEContainer(v *ResetIEContainer, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIEContainer(v *ResetIEContainer, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIEField(&(*v)[i], s)
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
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(v *s12.UECapabilityInfoIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(v *s12.UECapabilityInfoIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextModificationConfirmIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(v *s23.UEContextModificationConfirmIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextModificationFailureIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(v *s23.UEContextModificationFailureIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UE-associatedLogicalS1-ConnectionItemRes}} of TS 36.413: a single information element field.
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer = UEAssociatedLogicalS1ConnectionItemResIEField

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UE-associatedLogicalS1-ConnectionItemResAck}} of TS 36.413: a single information element field.
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

// ResetCauseIEBinding binds Cause to the ResetIEs object set of TS 36.413.
type ResetCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) ResetIEValue

	get func(*ResetIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ResetCauseIEBinding) New(value s14.Cause,

) (ResetIEField, error) {
	if b.inject == nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetCauseIEBinding) Get(field *ResetIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetResetTypeIEBinding binds ResetType to the ResetIEs object set of TS 36.413.
type ResetResetTypeIEBinding struct {
	info   s00.FieldInfo
	codec  ResetTypeValueCodec
	inject func(ResetType,

	) ResetIEValue

	get func(*ResetIEValue,

	) (*ResetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetResetTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetResetTypeIEBinding) Codec() ResetTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ResetResetTypeIEBinding) New(value ResetType,

) (ResetIEField, error) {
	if b.inject == nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetResetTypeIEBinding) Get(field *ResetIEField) (*ResetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetTypeValueCodec is the concrete ValueCodec[ResetType].
type ResetTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetType,

		error)
	encode func(ResetType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetType, aper.DecodeState,

	) (ResetType, aper.Snapshot,

	)
	compare func(ResetType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetTypeValueCodec) New(value ResetType,

) (ResetTypeAPERValue, error) {
	if c.encode == nil {
		return ResetTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetTypeValueCodec) EncodeAPER(value ResetTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetTypeValueCodec) encodeBudgetValue(value ResetType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetTypeValueCodec) encodeChanged(value ResetType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding binds UEAssociatedLogicalS1ConnectionItem to the UE-associatedLogicalS1-ConnectionItemRes object set of TS 36.413.
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

// UEAssociatedLogicalS1ConnectionItemResIEField is ProtocolIE-Field {{UE-associatedLogicalS1-ConnectionItemRes}} of TS 36.413: an information element field.
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

// UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding binds UEAssociatedLogicalS1ConnectionItem to the UE-associatedLogicalS1-ConnectionItemResAck object set of TS 36.413.
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

// UEAssociatedLogicalS1ConnectionItemResAckIEField is ProtocolIE-Field {{UE-associatedLogicalS1-ConnectionItemResAck}} of TS 36.413: an information element field.
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

// ResetValueCodec is the concrete ValueCodec[Reset].
type ResetValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Reset,

		error)
	encode func(Reset,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Reset, aper.DecodeState,

	) (Reset, aper.Snapshot,

	)
	compare func(Reset, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetValueCodec) New(value Reset,

) (ResetAPERValue, error) {
	if c.encode == nil {
		return ResetAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetValueCodec) EncodeAPER(value ResetAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetValueCodec) encodeBudgetValue(value Reset,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetValueCodec) encodeChanged(value Reset,

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

// UECapabilityInfoIndicationValueCodec is the concrete ValueCodec[UECapabilityInfoIndication].
type UECapabilityInfoIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UECapabilityInfoIndication,

		error)
	encode func(UECapabilityInfoIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UECapabilityInfoIndication, aper.DecodeState,

	) (UECapabilityInfoIndication, aper.Snapshot,

	)
	compare func(UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UECapabilityInfoIndicationValueCodec) New(value UECapabilityInfoIndication,

) (UECapabilityInfoIndicationAPERValue, error) {
	if c.encode == nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UECapabilityInfoIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UECapabilityInfoIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UECapabilityInfoIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UECapabilityInfoIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UECapabilityInfoIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UECapabilityInfoIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UECapabilityInfoIndicationValueCodec) EncodeAPER(value UECapabilityInfoIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UECapabilityInfoIndicationValueCodec) encodeBudgetValue(value UECapabilityInfoIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UECapabilityInfoIndicationValueCodec) encodeChanged(value UECapabilityInfoIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmValueCodec is the concrete ValueCodec[UEContextModificationConfirm].
type UEContextModificationConfirmValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirm,

		error)
	encode func(UEContextModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirm, aper.DecodeState,

	) (UEContextModificationConfirm, aper.Snapshot,

	)
	compare func(UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmValueCodec) New(value UEContextModificationConfirm,

) (UEContextModificationConfirmAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmValueCodec) EncodeAPER(value UEContextModificationConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationConfirmValueCodec) encodeBudgetValue(value UEContextModificationConfirm,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmValueCodec) encodeChanged(value UEContextModificationConfirm,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureValueCodec is the concrete ValueCodec[UEContextModificationFailure].
type UEContextModificationFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailure,

		error)
	encode func(UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailure, aper.DecodeState,

	) (UEContextModificationFailure, aper.Snapshot,

	)
	compare func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureValueCodec) New(value UEContextModificationFailure,

) (UEContextModificationFailureAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureValueCodec) EncodeAPER(value UEContextModificationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationFailureValueCodec) encodeBudgetValue(value UEContextModificationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureValueCodec) encodeChanged(value UEContextModificationFailure,

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
func BridgeHandoverNotifyIEValueValidateS1APIEContainer(fields s35.HandoverNotifyIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s35.BridgeHandoverNotifyIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s35.BridgeHandoverNotifyIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s35.BridgeHandoverNotifyIEValueMethodRule(field.Value).Assignment
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
func BridgeInitialUEMessageIEValueValidateS1APIEContainer(fields s35.InitialUEMessageIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s35.BridgeInitialUEMessageIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s35.BridgeInitialUEMessageIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s35.BridgeInitialUEMessageIEValueMethodRule(field.Value).Assignment
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
func BridgeResetIEValueValidateS1APIEContainer(fields ResetIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(fields s12.UECapabilityInfoIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s12.BridgeUECapabilityInfoIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s12.BridgeUECapabilityInfoIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s12.BridgeUECapabilityInfoIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(fields s23.UEContextModificationConfirmIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUEContextModificationConfirmIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUEContextModificationConfirmIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUEContextModificationConfirmIEValueMethodRule(field.Value).Assignment
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
func BridgeTunnelInformationExtIEsValueValidateS1APExtensionContainer(fields s12.TunnelInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueValidateS1APIEContainer(fields UEAssociatedLogicalS1ConnectionItemResIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// UEAssociatedLogicalS1ConnectionItemResIEContainer is ProtocolIE-Container {{UE-associatedLogicalS1-ConnectionItemRes}} of TS 36.413: a list of UEAssociatedLogicalS1ConnectionItemResIEField values.
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

// UEAssociatedLogicalS1ConnectionItemResAckIEContainer is ProtocolIE-Container {{UE-associatedLogicalS1-ConnectionItemResAck}} of TS 36.413: a list of UEAssociatedLogicalS1ConnectionItemResAckIEField values.
type UEAssociatedLogicalS1ConnectionItemResAckIEContainer []UEAssociatedLogicalS1ConnectionItemResAckIEField

// HandoverNotifyIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverNotifyIEs}} codec of TS 36.413.
func HandoverNotifyIEValueERABIEContainerListCodec(table s00.HandoverNotifyIEValueIETable) s35.HandoverNotifyIEValueERABIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeHandoverNotifyIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.HandoverNotifyIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s35.HandoverNotifyIEValueERABIEContainerListValueCodec {
		sealed := s35.HandoverNotifyIEValueERABIEContainerListValueCodec{}
		*s35.BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.HandoverNotifyIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.HandoverNotifyIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.HandoverNotifyIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverNotifyIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.HandoverNotifyIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeHandoverNotifyIEContainerValueCodecFieldEncode(&codec))(s35.HandoverNotifyIEContainer(value), fresh, budget)
		}
		*s35.BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.HandoverNotifyIEValueERABIEContainerList, options aper.DecodeState) (s35.HandoverNotifyIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s35.BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.HandoverNotifyIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeHandoverNotifyIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialUEMessageIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{InitialUEMessage-IEs}} codec of TS 36.413.
func InitialUEMessageIEValueERABIEContainerListCodec(table s00.InitialUEMessageIEValueIETable) s35.InitialUEMessageIEValueERABIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeInitialUEMessageIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.InitialUEMessageIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s35.InitialUEMessageIEValueERABIEContainerListValueCodec {
		sealed := s35.InitialUEMessageIEValueERABIEContainerListValueCodec{}
		*s35.BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.InitialUEMessageIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.InitialUEMessageIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.InitialUEMessageIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialUEMessageIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.InitialUEMessageIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeInitialUEMessageIEContainerValueCodecFieldEncode(&codec))(s35.InitialUEMessageIEContainer(value), fresh, budget)
		}
		*s35.BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.InitialUEMessageIEValueERABIEContainerList, options aper.DecodeState) (s35.InitialUEMessageIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s35.BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.InitialUEMessageIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeInitialUEMessageIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ResetIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ResetIEs}} codec of TS 36.413.
func ResetIEValueERABIEContainerListCodec(table s00.ResetIEValueIETable) ResetIEValueERABIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ResetIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueERABIEContainerList, options aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ResetIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemResAck}} codec of TS 36.413.
func UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable) UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResAckIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResAckIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemRes}} codec of TS 36.413.
func UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable) UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UECapabilityInfoIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UECapabilityInfoIndicationIEs}} codec of TS 36.413.
func UECapabilityInfoIndicationIEValueERABIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UECapabilityInfoIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UECapabilityInfoIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueERABIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationConfirmIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationConfirmIEs}} codec of TS 36.413.
func UEContextModificationConfirmIEValueERABIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationConfirmIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationConfirmIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirmIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueERABIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UEAggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEAggregateMaximumBitratesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAggregateMaximumBitratesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEAggregateMaximumBitratesExtIEsExtField")
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAggregateMaximumBitratesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// UEAppLayerMeasConfigExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UEAppLayerMeasConfig-ExtIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEAppLayerMeasConfigExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAppLayerMeasConfigExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEAppLayerMeasConfigExtIEsExtField")
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAppLayerMeasConfigExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEAppLayerMeasConfigExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-associatedLogicalS1-ConnectionItemExtIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemExtIEsExtField")
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// UEAggregateMaximumBitratesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UEAggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEAggregateMaximumBitratesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAggregateMaximumBitratesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEAggregateMaximumBitratesExtIEsExtContainer")
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
			f := s.Begin()
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

// UEAppLayerMeasConfigExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UEAppLayerMeasConfig-ExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEAppLayerMeasConfigExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAppLayerMeasConfigExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEAppLayerMeasConfigExtIEsExtContainer")
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
			f := s.Begin()
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

// UEAssociatedLogicalS1ConnectionItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-associatedLogicalS1-ConnectionItemExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer")
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
			f := s.Begin()
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

// HandoverNotifyIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverNotifyIEs}} codec of TS 36.413.
func HandoverNotifyIEValueIEFieldTableCodec(table s00.HandoverNotifyIEValueIETable) s35.HandoverNotifyIEFieldValueCodec {
	if !*s00.BridgeHandoverNotifyIEValueIETableFieldBound(&table) {
		return s35.HandoverNotifyIEFieldValueCodec{}
	}
	return func() s35.HandoverNotifyIEFieldValueCodec {
		sealed := s35.HandoverNotifyIEFieldValueCodec{}
		*s35.BridgeHandoverNotifyIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.HandoverNotifyIEField, error) {
			var field s35.HandoverNotifyIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverNotifyIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverNotifyIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverNotifyIEField")
			}
			return field, nil
		}
		*s35.BridgeHandoverNotifyIEFieldValueCodecFieldEncode(&sealed) = func(field s35.HandoverNotifyIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s35.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s35.BridgeHandoverNotifyIEFieldValueCodecFieldCapture(&sealed) = func(v s35.HandoverNotifyIEField, options aper.DecodeState) (s35.HandoverNotifyIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeHandoverNotifyIEFieldValueCodecFieldCompare(&sealed) = func(v s35.HandoverNotifyIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeHandoverNotifyIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialUEMessageIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{InitialUEMessage-IEs}} codec of TS 36.413.
func InitialUEMessageIEValueIEFieldTableCodec(table s00.InitialUEMessageIEValueIETable) s35.InitialUEMessageIEFieldValueCodec {
	if !*s00.BridgeInitialUEMessageIEValueIETableFieldBound(&table) {
		return s35.InitialUEMessageIEFieldValueCodec{}
	}
	return func() s35.InitialUEMessageIEFieldValueCodec {
		sealed := s35.InitialUEMessageIEFieldValueCodec{}
		*s35.BridgeInitialUEMessageIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.InitialUEMessageIEField, error) {
			var field s35.InitialUEMessageIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "InitialUEMessageIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialUEMessageIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "InitialUEMessageIEField")
			}
			return field, nil
		}
		*s35.BridgeInitialUEMessageIEFieldValueCodecFieldEncode(&sealed) = func(field s35.InitialUEMessageIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s35.BridgeInitialUEMessageIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s35.BridgeInitialUEMessageIEFieldValueCodecFieldCapture(&sealed) = func(v s35.InitialUEMessageIEField, options aper.DecodeState) (s35.InitialUEMessageIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeInitialUEMessageIEFieldValueCodecFieldCompare(&sealed) = func(v s35.InitialUEMessageIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeInitialUEMessageIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ResetIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ResetIEs}} codec of TS 36.413.
func ResetIEValueIEFieldTableCodec(table s00.ResetIEValueIETable) ResetIEFieldValueCodec {
	if !*s00.BridgeResetIEValueIETableFieldBound(&table) {
		return ResetIEFieldValueCodec{}
	}
	return ResetIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEField, error) {
		var field ResetIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ResetIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ResetIEField")
		}
		return field, nil
	}, encode: func(field ResetIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ResetIEField, options aper.DecodeState) (ResetIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APProtocolIEField(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UE-associatedLogicalS1-ConnectionItemResAck}} codec of TS 36.413.
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
			return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResAckIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEField")
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
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
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

// UEAssociatedLogicalS1ConnectionItemResIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UE-associatedLogicalS1-ConnectionItemRes}} codec of TS 36.413.
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
			return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEField")
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
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
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

// UECapabilityInfoIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UECapabilityInfoIndicationIEs}} codec of TS 36.413.
func UECapabilityInfoIndicationIEValueIEFieldTableCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEFieldValueCodec {
	if !*s00.BridgeUECapabilityInfoIndicationIEValueIETableFieldBound(&table) {
		return s12.UECapabilityInfoIndicationIEFieldValueCodec{}
	}
	return func() s12.UECapabilityInfoIndicationIEFieldValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEFieldValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEField, error) {
			var field s12.UECapabilityInfoIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEField")
			}
			return field, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UECapabilityInfoIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEField, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationConfirmIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationConfirmIEs}} codec of TS 36.413.
func UEContextModificationConfirmIEValueIEFieldTableCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationConfirmIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationConfirmIEFieldValueCodec{}
	}
	return func() s23.UEContextModificationConfirmIEFieldValueCodec {
		sealed := s23.UEContextModificationConfirmIEFieldValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEField, error) {
			var field s23.UEContextModificationConfirmIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirmIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEField")
			}
			return field, nil
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextModificationConfirmIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEField, options aper.DecodeState) (s23.UEContextModificationConfirmIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueIEFieldTableCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationFailureIEFieldValueCodec{}
	}
	return func() s23.UEContextModificationFailureIEFieldValueCodec {
		sealed := s23.UEContextModificationFailureIEFieldValueCodec{}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEField, error) {
			var field s23.UEContextModificationFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationFailureIEField")
			}
			return field, nil
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextModificationFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEField, options aper.DecodeState) (s23.UEContextModificationFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverNotifyIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverNotifyIEs}} codec of TS 36.413.
func HandoverNotifyIEValueIETableCodec(table s00.HandoverNotifyIEValueIETable, bounds aper.ListBounds) s35.HandoverNotifyIEContainerValueCodec {
	if !*s00.BridgeHandoverNotifyIEValueIETableFieldBound(&table) {
		return s35.HandoverNotifyIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s35.HandoverNotifyIEContainerValueCodec {
		sealed := s35.HandoverNotifyIEContainerValueCodec{}
		*s35.BridgeHandoverNotifyIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.HandoverNotifyIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.HandoverNotifyIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.HandoverNotifyIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverNotifyIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEContainer")
			}
			return fields, nil
		}
		*s35.BridgeHandoverNotifyIEContainerValueCodecFieldEncode(&sealed) = func(fields s35.HandoverNotifyIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s35.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s35.BridgeHandoverNotifyIEContainerValueCodecFieldCapture(&sealed) = func(v s35.HandoverNotifyIEContainer, options aper.DecodeState) (s35.HandoverNotifyIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s35.BridgeHandoverNotifyIEContainerValueCodecFieldCompare(&sealed) = func(v s35.HandoverNotifyIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeHandoverNotifyIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialUEMessageIEValueIETableCodec constructs the ProtocolIE-Container {{InitialUEMessage-IEs}} codec of TS 36.413.
func InitialUEMessageIEValueIETableCodec(table s00.InitialUEMessageIEValueIETable, bounds aper.ListBounds) s35.InitialUEMessageIEContainerValueCodec {
	if !*s00.BridgeInitialUEMessageIEValueIETableFieldBound(&table) {
		return s35.InitialUEMessageIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s35.InitialUEMessageIEContainerValueCodec {
		sealed := s35.InitialUEMessageIEContainerValueCodec{}
		*s35.BridgeInitialUEMessageIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.InitialUEMessageIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.InitialUEMessageIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.InitialUEMessageIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialUEMessageIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEContainer")
			}
			return fields, nil
		}
		*s35.BridgeInitialUEMessageIEContainerValueCodecFieldEncode(&sealed) = func(fields s35.InitialUEMessageIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s35.BridgeInitialUEMessageIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s35.BridgeInitialUEMessageIEContainerValueCodecFieldCapture(&sealed) = func(v s35.InitialUEMessageIEContainer, options aper.DecodeState) (s35.InitialUEMessageIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s35.BridgeInitialUEMessageIEContainerValueCodecFieldCompare(&sealed) = func(v s35.InitialUEMessageIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeInitialUEMessageIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ResetIEValueIETableCodec constructs the ProtocolIE-Container {{ResetIEs}} codec of TS 36.413.
func ResetIEValueIETableCodec(table s00.ResetIEValueIETable, bounds aper.ListBounds) ResetIEContainerValueCodec {
	if !*s00.BridgeResetIEValueIETableFieldBound(&table) {
		return ResetIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ResetIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ResetIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ResetIEContainer, options aper.DecodeState) (ResetIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeResetIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ResetIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeResetIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec constructs the ProtocolIE-Container {{UE-associatedLogicalS1-ConnectionItemResAck}} codec of TS 36.413.
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResAckIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec constructs the ProtocolIE-Container {{UE-associatedLogicalS1-ConnectionItemRes}} codec of TS 36.413.
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UECapabilityInfoIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{UECapabilityInfoIndicationIEs}} codec of TS 36.413.
func UECapabilityInfoIndicationIEValueIETableCodec(table s00.UECapabilityInfoIndicationIEValueIETable, bounds aper.ListBounds) s12.UECapabilityInfoIndicationIEContainerValueCodec {
	if !*s00.BridgeUECapabilityInfoIndicationIEValueIETableFieldBound(&table) {
		return s12.UECapabilityInfoIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UECapabilityInfoIndicationIEContainerValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEContainerValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UECapabilityInfoIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UECapabilityInfoIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEContainer")
			}
			return fields, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UECapabilityInfoIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEContainer, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationConfirmIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationConfirmIEs}} codec of TS 36.413.
func UEContextModificationConfirmIEValueIETableCodec(table s00.UEContextModificationConfirmIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationConfirmIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationConfirmIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationConfirmIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationConfirmIEContainerValueCodec {
		sealed := s23.UEContextModificationConfirmIEContainerValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationConfirmIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationConfirmIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirmIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEContainer")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextModificationConfirmIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEContainer, options aper.DecodeState) (s23.UEContextModificationConfirmIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationFailureIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueIETableCodec(table s00.UEContextModificationFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationFailureIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationFailureIEContainerValueCodec {
		sealed := s23.UEContextModificationFailureIEContainerValueCodec{}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEContainer")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextModificationFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEContainer, options aper.DecodeState) (s23.UEContextModificationFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverNotifyIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverNotifyIEs}} codec of TS 36.413.
func HandoverNotifyIEValueProtocolErrorIEContainerListCodec(table s00.HandoverNotifyIEValueIETable) s35.HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeHandoverNotifyIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s35.HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s35.HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec{}
		*s35.BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.HandoverNotifyIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.HandoverNotifyIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.HandoverNotifyIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverNotifyIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.HandoverNotifyIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeHandoverNotifyIEContainerValueCodecFieldEncode(&codec))(s35.HandoverNotifyIEContainer(value), fresh, budget)
		}
		*s35.BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.HandoverNotifyIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s35.HandoverNotifyIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.HandoverNotifyIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeHandoverNotifyIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialUEMessageIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{InitialUEMessage-IEs}} codec of TS 36.413.
func InitialUEMessageIEValueProtocolErrorIEContainerListCodec(table s00.InitialUEMessageIEValueIETable) s35.InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeInitialUEMessageIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s35.InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s35.InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec{}
		*s35.BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.InitialUEMessageIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.InitialUEMessageIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.InitialUEMessageIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialUEMessageIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.InitialUEMessageIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeInitialUEMessageIEContainerValueCodecFieldEncode(&codec))(s35.InitialUEMessageIEContainer(value), fresh, budget)
		}
		*s35.BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.InitialUEMessageIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s35.InitialUEMessageIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.InitialUEMessageIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeInitialUEMessageIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ResetIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ResetIEs}} codec of TS 36.413.
func ResetIEValueProtocolErrorIEContainerListCodec(table s00.ResetIEValueIETable) ResetIEValueProtocolErrorIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ResetIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APProtocolErrorIEContainerList(
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemResAck}} codec of TS 36.413.
func UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable) UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResAckIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
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
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolErrorIEContainerList(
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemRes}} codec of TS 36.413.
func UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable) UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolErrorIEContainerList(
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

// UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UECapabilityInfoIndicationIEs}} codec of TS 36.413.
func UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UECapabilityInfoIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationConfirmIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationConfirmIEs}} codec of TS 36.413.
func UEContextModificationConfirmIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationConfirmIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirmIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverNotifyIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverNotifyIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverNotifyIEValueProtocolIEContainerListCodec(table s00.HandoverNotifyIEValueIETable, bounds aper.ListBounds) s35.HandoverNotifyIEValueProtocolIEContainerListValueCodec {
	codec := HandoverNotifyIEValueIETableCodec(table, bounds)
	if *s35.BridgeHandoverNotifyIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.HandoverNotifyIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s35.HandoverNotifyIEValueProtocolIEContainerListValueCodec {
		sealed := s35.HandoverNotifyIEValueProtocolIEContainerListValueCodec{}
		*s35.BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.HandoverNotifyIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.HandoverNotifyIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.HandoverNotifyIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverNotifyIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverNotifyIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.HandoverNotifyIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeHandoverNotifyIEContainerValueCodecFieldEncode(&codec))(s35.HandoverNotifyIEContainer(value), fresh, budget)
		}
		*s35.BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.HandoverNotifyIEValueProtocolIEContainerList, options aper.DecodeState) (s35.HandoverNotifyIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s35.BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.HandoverNotifyIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeHandoverNotifyIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialUEMessageIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {InitialUEMessage-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func InitialUEMessageIEValueProtocolIEContainerListCodec(table s00.InitialUEMessageIEValueIETable, bounds aper.ListBounds) s35.InitialUEMessageIEValueProtocolIEContainerListValueCodec {
	codec := InitialUEMessageIEValueIETableCodec(table, bounds)
	if *s35.BridgeInitialUEMessageIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.InitialUEMessageIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s35.InitialUEMessageIEValueProtocolIEContainerListValueCodec {
		sealed := s35.InitialUEMessageIEValueProtocolIEContainerListValueCodec{}
		*s35.BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.InitialUEMessageIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s35.InitialUEMessageIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s35.InitialUEMessageIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "InitialUEMessageIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "InitialUEMessageIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s35.BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.InitialUEMessageIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeInitialUEMessageIEContainerValueCodecFieldEncode(&codec))(s35.InitialUEMessageIEContainer(value), fresh, budget)
		}
		*s35.BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.InitialUEMessageIEValueProtocolIEContainerList, options aper.DecodeState) (s35.InitialUEMessageIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s35.BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.InitialUEMessageIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeInitialUEMessageIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ResetIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ResetIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ResetIEValueProtocolIEContainerListCodec(table s00.ResetIEValueIETable, bounds aper.ListBounds) ResetIEValueProtocolIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ResetIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ResetIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetIEField
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
			return nil, runtime.WrapDecodePath(err, "ResetIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ResetIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ResetIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ResetIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueProtocolIEContainerList, options aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ResetIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeResetIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UE-associatedLogicalS1-ConnectionItemResAck} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResAckIEValueIETable, bounds aper.ListBounds) UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResAckIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResAckIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResAckIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UE-associatedLogicalS1-ConnectionItemRes} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable, bounds aper.ListBounds) UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec {
	codec := UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEAssociatedLogicalS1ConnectionItemResIEField
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
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
	}, capture: func(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UECapabilityInfoIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UECapabilityInfoIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UECapabilityInfoIndicationIEValueProtocolIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable, bounds aper.ListBounds) s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, bounds)
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UECapabilityInfoIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UECapabilityInfoIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationConfirmIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationConfirmIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationConfirmIEValueProtocolIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationConfirmIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationConfirmIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirmIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationConfirmIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// handoverNotifyIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverNotifyIEValue].
type HandoverNotifyIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s35.HandoverNotifyIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s35.HandoverNotifyIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(v *s35.HandoverNotifyIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s35.BridgeHandoverNotifyIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s35.BridgeHandoverNotifyIEFieldFieldReplay(v), *s35.BridgeHandoverNotifyIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(v *s35.HandoverNotifyIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s35.BridgeHandoverNotifyIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s35.BridgeHandoverNotifyIEFieldFieldReplay(v), *s35.BridgeHandoverNotifyIEFieldFieldWithoutReplay(v))
}

// initialUEMessageIEValueProtocolOpenValue is the concrete protocolOpenValue[InitialUEMessageIEValue].
type InitialUEMessageIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s35.InitialUEMessageIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s35.InitialUEMessageIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(v *s35.InitialUEMessageIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s35.BridgeInitialUEMessageIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s35.BridgeInitialUEMessageIEFieldFieldReplay(v), *s35.BridgeInitialUEMessageIEFieldFieldWithoutReplay(v))
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(v *s35.InitialUEMessageIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s35.BridgeInitialUEMessageIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s35.BridgeInitialUEMessageIEFieldFieldReplay(v), *s35.BridgeInitialUEMessageIEFieldFieldWithoutReplay(v))
}

// resetIEValueProtocolOpenValue is the concrete protocolOpenValue[ResetIEValue].
type ResetIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ResetIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ResetIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResetIEValueCaptureS1APProtocolIEField(v *ResetIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResetIEValueCompareS1APProtocolIEField(v *ResetIEField, s *aper.SemanticComparison) {
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

// uEAssociatedLogicalS1ConnectionItemResIEValueProtocolOpenValue is the concrete protocolOpenValue[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEAssociatedLogicalS1ConnectionItemResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEAssociatedLogicalS1ConnectionItemResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
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

// uECapabilityInfoIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[UECapabilityInfoIndicationIEValue].
type UECapabilityInfoIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.UECapabilityInfoIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.UECapabilityInfoIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(v *s12.UECapabilityInfoIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeUECapabilityInfoIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUECapabilityInfoIndicationIEFieldFieldReplay(v), *s12.BridgeUECapabilityInfoIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(v *s12.UECapabilityInfoIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeUECapabilityInfoIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUECapabilityInfoIndicationIEFieldFieldReplay(v), *s12.BridgeUECapabilityInfoIndicationIEFieldFieldWithoutReplay(v))
}

// uEContextModificationConfirmIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UEContextModificationConfirmIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UEContextModificationConfirmIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(v *s23.UEContextModificationConfirmIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextModificationConfirmIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextModificationConfirmIEFieldFieldReplay(v), *s23.BridgeUEContextModificationConfirmIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(v *s23.UEContextModificationConfirmIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextModificationConfirmIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextModificationConfirmIEFieldFieldReplay(v), *s23.BridgeUEContextModificationConfirmIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(v *s23.UEContextModificationFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextModificationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextModificationFailureIEFieldFieldReplay(v), *s23.BridgeUEContextModificationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(v *s23.UEContextModificationFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextModificationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextModificationFailureIEFieldFieldReplay(v), *s23.BridgeUEContextModificationFailureIEFieldFieldWithoutReplay(v))
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

// ResetTypeAPERValue is the concrete APERValue[ResetType].
type ResetTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResetType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetTypeAPERValue) WithoutReplay() ResetTypeAPERValue {
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

// ResetAPERValue is the concrete APERValue[Reset].
type ResetAPERValue struct {
	context s00.BridgeCodecContext
	Value   Reset

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAPERValue) WithoutReplay() ResetAPERValue {
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

// UECapabilityInfoIndicationAPERValue is the concrete APERValue[UECapabilityInfoIndication].
type UECapabilityInfoIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   UECapabilityInfoIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UECapabilityInfoIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UECapabilityInfoIndicationAPERValue) WithoutReplay() UECapabilityInfoIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmAPERValue is the concrete APERValue[UEContextModificationConfirm].
type UEContextModificationConfirmAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationConfirm

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmAPERValue) WithoutReplay() UEContextModificationConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureAPERValue is the concrete APERValue[UEContextModificationFailure].
type UEContextModificationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureAPERValue) WithoutReplay() UEContextModificationFailureAPERValue {
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeHandoverNotifyIEValueCaptureS1APERABIEContainerList(v *s35.HandoverNotifyIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeHandoverNotifyIEValueCompareS1APERABIEContainerList(v *s35.HandoverNotifyIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeInitialUEMessageIEValueCaptureS1APERABIEContainerList(v *s35.InitialUEMessageIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeInitialUEMessageIEValueCompareS1APERABIEContainerList(v *s35.InitialUEMessageIEValueERABIEContainerList, s *aper.SemanticComparison) {
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

// ResetIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ResetIEValueERABIEContainerList].
type ResetIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueERABIEContainerList, error)
	encode  func(ResetIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueERABIEContainerList, aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot)
	compare func(ResetIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueERABIEContainerListValueCodec) New(value ResetIEValueERABIEContainerList) (ResetIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueERABIEContainerListValueCodec) EncodeAPER(value ResetIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueERABIEContainerListValueCodec) encodeChanged(value ResetIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ResetIEs}} of TS 36.413: a list of information element fields.
type ResetIEValueERABIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APERABIEContainerList(v *ResetIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APERABIEContainerList(v *ResetIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemResAck}} of TS 36.413: a list of information element fields.
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

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemRes}} of TS 36.413: a list of information element fields.
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
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APERABIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APERABIEContainerList(v *s12.UECapabilityInfoIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APERABIEContainerList(v *s12.UECapabilityInfoIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APERABIEContainerList(v *s23.UEContextModificationConfirmIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APERABIEContainerList(v *s23.UEContextModificationConfirmIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APERABIEContainerList(v *s23.UEContextModificationFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(v *s23.UEContextModificationFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEFieldValueCodec is the concrete ValueCodec[ResetIEField].
type ResetIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEField, error)
	encode  func(ResetIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEField, aper.DecodeState) (ResetIEField, aper.Snapshot)
	compare func(ResetIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEFieldValueCodec) New(value ResetIEField) (ResetIEFieldAPERValue, error) {
	if c.encode == nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEFieldValueCodec) EncodeAPER(value ResetIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEFieldValueCodec) encodeBudgetValue(value ResetIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEFieldValueCodec) encodeChanged(value ResetIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEFieldValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResAckIEField].
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

// UEAssociatedLogicalS1ConnectionItemResIEFieldValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResIEField].
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

// ResetIEContainerValueCodec is the concrete ValueCodec[ResetIEContainer].
type ResetIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEContainer, error)
	encode  func(ResetIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEContainer, aper.DecodeState) (ResetIEContainer, aper.Snapshot)
	compare func(ResetIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEContainerValueCodec) New(value ResetIEContainer) (ResetIEContainerAPERValue, error) {
	if c.encode == nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEContainerValueCodec) EncodeAPER(value ResetIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEContainerValueCodec) encodeBudgetValue(value ResetIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEContainerValueCodec) encodeChanged(value ResetIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEContainerValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResAckIEContainer].
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

// UEAssociatedLogicalS1ConnectionItemResIEContainerValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResIEContainer].
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
func BridgeHandoverNotifyIEValueCaptureS1APProtocolErrorIEContainerList(v *s35.HandoverNotifyIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeHandoverNotifyIEValueCompareS1APProtocolErrorIEContainerList(v *s35.HandoverNotifyIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeInitialUEMessageIEValueCaptureS1APProtocolErrorIEContainerList(v *s35.InitialUEMessageIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeInitialUEMessageIEValueCompareS1APProtocolErrorIEContainerList(v *s35.InitialUEMessageIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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

// ResetIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ResetIEValueProtocolErrorIEContainerList].
type ResetIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error)
	encode  func(ResetIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ResetIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) New(value ResetIEValueProtocolErrorIEContainerList) (ResetIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ResetIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ResetIEs}} of TS 36.413: a list of information element fields.
type ResetIEValueProtocolErrorIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APProtocolErrorIEContainerList(v *ResetIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolErrorIEContainerList(v *ResetIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemResAck}} of TS 36.413: a list of information element fields.
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UE-associatedLogicalS1-ConnectionItemRes}} of TS 36.413: a list of information element fields.
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
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolErrorIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverNotifyIEValueCaptureS1APProtocolIEContainerList(v *s35.HandoverNotifyIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeHandoverNotifyIEValueCompareS1APProtocolIEContainerList(v *s35.HandoverNotifyIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeInitialUEMessageIEValueCaptureS1APProtocolIEContainerList(v *s35.InitialUEMessageIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeInitialUEMessageIEValueCompareS1APProtocolIEContainerList(v *s35.InitialUEMessageIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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

// ResetIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ResetIEValueProtocolIEContainerList].
type ResetIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueProtocolIEContainerList, error)
	encode  func(ResetIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueProtocolIEContainerList, aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ResetIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueProtocolIEContainerListValueCodec) New(value ResetIEValueProtocolIEContainerList) (ResetIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ResetIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueProtocolIEContainerListValueCodec) encodeChanged(value ResetIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ResetIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ResetIEValueProtocolIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APProtocolIEContainerList(v *ResetIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIEContainerList(v *ResetIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UE-associatedLogicalS1-ConnectionItemResAck} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UE-associatedLogicalS1-ConnectionItemRes} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
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
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainerList(v *UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCaptureS1APProtocolIESingleContainer(v *s35.HandoverNotifyIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverNotifyIEValueCompareS1APProtocolIESingleContainer(v *s35.HandoverNotifyIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverNotifyIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialUEMessageIEValueCaptureS1APProtocolIESingleContainer(v *s35.InitialUEMessageIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeInitialUEMessageIEValueCompareS1APProtocolIESingleContainer(v *s35.InitialUEMessageIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialUEMessageIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEValueERABIEContainerListAPERValue is the concrete APERValue[ResetIEValueERABIEContainerList].
type ResetIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueERABIEContainerListAPERValue) WithoutReplay() ResetIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ResetIEs}} of TS 36.413: a single information element field.
type ResetIEValueProtocolIESingleContainer = ResetIEField

func BridgeResetIEValueCaptureS1APProtocolIESingleContainer(v *ResetIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIESingleContainer(v *ResetIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResAckIEValueERABIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList].
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
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s12.UECapabilityInfoIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(v *s12.UECapabilityInfoIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextModificationFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextModificationFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEFieldAPERValue is the concrete APERValue[ResetIEField].
type ResetIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEFieldAPERValue) WithoutReplay() ResetIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEFieldAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResAckIEField].
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

// UEAssociatedLogicalS1ConnectionItemResIEFieldAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResIEField].
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

// ResetIEContainerAPERValue is the concrete APERValue[ResetIEContainer].
type ResetIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEContainerAPERValue) WithoutReplay() ResetIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEContainerAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResAckIEContainer].
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

// UEAssociatedLogicalS1ConnectionItemResIEContainerAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResIEContainer].
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

// ResetIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ResetIEValueProtocolErrorIEContainerList].
type ResetIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ResetIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolErrorIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList].
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

// ResetIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ResetIEValueProtocolIEContainerList].
type ResetIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueProtocolIEContainerListAPERValue) WithoutReplay() ResetIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIEContainerList].
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

// UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList].
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
func BridgeCaptureS1APReset(v *Reset, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APReset(v *Reset, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APResetIEValue(v *ResetIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(92):
			{
				f := s.Begin()
				s.Bool(v.rowResetType == nil)
				if v.rowResetType != nil {
					BridgeCaptureS1APResetType(v.rowResetType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetIEValue) captureSemantics(s aper.SemanticCapture) ResetIEValue {
	BridgeCaptureS1APResetIEValue(&v, &s)
	return v
}
func BridgeCompareS1APResetIEValue(v *ResetIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(92):
			{
				f := s.Begin()
				s.Bool(v.rowResetType == nil)
				if v.rowResetType != nil {
					BridgeCompareS1APResetType(v.rowResetType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APResetIEValue(&v, &s)
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
	s33.BridgeCaptureS1APAreaScopeOfQMC(&v.AreaScopeOfQMC, s)
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
	s33.BridgeCompareS1APAreaScopeOfQMC(&v.AreaScopeOfQMC, s)
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
func BridgeCaptureS1APUECapabilityInfoIndication(v *UECapabilityInfoIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUECapabilityInfoIndication(v *UECapabilityInfoIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationConfirm(v *UEContextModificationConfirm, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationConfirm(v *UEContextModificationConfirm, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationFailure(v *UEContextModificationFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationFailure(v *UEContextModificationFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
	AreaScopeOfQMC                 s33.AreaScopeOfQMC                         `asn1:"tag:1,context,explicit"`
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
	bb.EnterComponent("UEAggregateMaximumBitrate")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UEAggregateMaximumBitratesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAggregateMaximumBitratesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUEAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := s33.BridgeAreaScopeOfQMCMethodMarshalAPERTo(&v.AreaScopeOfQMC, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("UEAppLayerMeasConfig")
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
	if err := s33.BridgeAreaScopeOfQMCMethodUnmarshalAPERFrom(&v.AreaScopeOfQMC, bb); err != nil {
		return runtime.WrapDecodePath(err, "AreaScopeOfQMC")
	}
	bb.LeaveComponent(toleranceMark_areascopeofqmc)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UEAppLayerMeasConfigExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAppLayerMeasConfigExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUEAppLayerMeasConfigExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("UEAssociatedLogicalS1ConnectionItem")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UEAssociatedLogicalS1ConnectionItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	ProtocolIEs      s35.HandoverNotifyIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationFailure represents the ASN.1 type UEContextModificationFailure (SEQUENCE).
type UEContextModificationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextModificationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
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
	ProtocolIEs      s35.InitialUEMessageIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// Reset represents the ASN.1 type Reset (SEQUENCE).
type Reset struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ResetIEContainer       `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
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

// NewResetTypeS1Interface creates a ResetType with the s1-Interface alternative.
func BridgeNewResetTypeS1InterfaceLegacy(v s00.ResetAll) ResetType {
	return ResetType{
		Choice:      s00.ResetTypeChoiceS1Interface,
		S1Interface: &v,
	}
}

// NewResetTypePartOfS1Interface creates a ResetType with the partOfS1-Interface alternative.
func BridgeNewResetTypePartOfS1InterfaceLegacy(v UEAssociatedLogicalS1ConnectionListRes) ResetType {
	return ResetType{
		Choice:            s00.ResetTypeChoicePartOfS1Interface,
		PartOfS1Interface: v,
	}
}

type UEAssociatedLogicalS1ConnectionListRes = []UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
type UEAssociatedLogicalS1ConnectionListResAck = []UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer

// UECapabilityInfoIndication represents the ASN.1 type UECapabilityInfoIndication (SEQUENCE).
type UECapabilityInfoIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UECapabilityInfoIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationConfirm represents the ASN.1 type UEContextModificationConfirm (SEQUENCE).
type UEContextModificationConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextModificationConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

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
			if err := s35.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("HandoverNotify")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s35.HandoverNotifyIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s35.HandoverNotifyIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s35.BridgeHandoverNotifyIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationFailure to APER format.
func (v *UEContextModificationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationFailure from APER format.
func (v *UEContextModificationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	bb.EnterComponent("UEContextModificationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextModificationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextModificationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s35.BridgeInitialUEMessageIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("InitialUEMessage")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s35.InitialUEMessageIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s35.InitialUEMessageIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s35.BridgeInitialUEMessageIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes Reset to APER format.
func (v *Reset) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Reset) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes Reset from APER format.
func (v *Reset) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Reset with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Reset) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	bb.EnterComponent("Reset")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	padding, err := aper.CaptureFinalBits(bb, "Reset")
	if err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *Reset) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Reset{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ResetIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ResetIEField
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
	bb.EnterComponent("ResetType")
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
		toleranceMark_partofs1interface := bb.EnterComponent("PartOfS1Interface")
		tmp_partofs1interface := make(UEAssociatedLogicalS1ConnectionListRes, 0)
		_, errCollection_partofs1interface := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_partofs1interface, fragmentLength_partofs1interface int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_partofs1interface < 0 || fragmentLength_partofs1interface < 0 || fragmentLength_partofs1interface > int64(^uint(0)>>1) || fragmentOffset_partofs1interface > int64(^uint(0)>>1)-fragmentLength_partofs1interface {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_partofs1interface; i++ {
				var elem UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
				elementMark := bb.EnterIndex(fragmentOffset_partofs1interface + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("PartOfS1Interface[%d]", fragmentOffset_partofs1interface+i))
				}
				bb.LeaveComponent(elementMark)
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
		bb.LeaveComponent(toleranceMark_partofs1interface)
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

// MarshalAPER encodes UECapabilityInfoIndication to APER format.
func (v *UECapabilityInfoIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UECapabilityInfoIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UECapabilityInfoIndication from APER format.
func (v *UECapabilityInfoIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UECapabilityInfoIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UECapabilityInfoIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	bb.EnterComponent("UECapabilityInfoIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UECapabilityInfoIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UECapabilityInfoIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UECapabilityInfoIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UECapabilityInfoIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationConfirm to APER format.
func (v *UEContextModificationConfirm) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationConfirm) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationConfirm from APER format.
func (v *UEContextModificationConfirm) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationConfirm) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	bb.EnterComponent("UEContextModificationConfirm")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationConfirm) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextModificationConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextModificationConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *Reset) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "Reset", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Reset", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Reset) WithoutReplay() Reset {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Reset
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UECapabilityInfoIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UECapabilityInfoIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UECapabilityInfoIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UECapabilityInfoIndication) WithoutReplay() UECapabilityInfoIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UECapabilityInfoIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationConfirm) WithoutReplay() UEContextModificationConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationFailure) WithoutReplay() UEContextModificationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
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

// Extensions returns owned unknown sequence additions.
func (v *Reset) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Reset) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Reset) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UECapabilityInfoIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UECapabilityInfoIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UECapabilityInfoIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
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
func (v *Reset) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Reset")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Reset) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Reset")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APReset(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Reset")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Reset")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Reset) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Reset")
}
func (v *Reset) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Reset")
}
func (v *Reset) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APReset(v, &s)
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
func (v *Reset) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Reset) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UECapabilityInfoIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UECapabilityInfoIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UECapabilityInfoIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUECapabilityInfoIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UECapabilityInfoIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UECapabilityInfoIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UECapabilityInfoIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UECapabilityInfoIndication")
}
func (v *UECapabilityInfoIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UECapabilityInfoIndication")
}
func (v *UECapabilityInfoIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUECapabilityInfoIndication(v, &s)
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
func (v *UECapabilityInfoIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UECapabilityInfoIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationConfirm")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationConfirm) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationConfirm")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationConfirm(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationConfirm")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationConfirm")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationConfirm) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationConfirm")
}
func (v *UEContextModificationConfirm) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationConfirm")
}
func (v *UEContextModificationConfirm) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationConfirm(v, &s)
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
func (v *UEContextModificationConfirm) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationConfirm) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationFailure")
}
func (v *UEContextModificationFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationFailure")
}
func (v *UEContextModificationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationFailure(v, &s)
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
func (v *UEContextModificationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Reset) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Reset")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Reset
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APReset(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Reset{}
		return report, aper.OperationError(err, "Reset")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Reset")
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UECapabilityInfoIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UECapabilityInfoIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UECapabilityInfoIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUECapabilityInfoIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UECapabilityInfoIndication{}
		return report, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UECapabilityInfoIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationConfirm")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationConfirm
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationConfirm{}
		return report, aper.OperationError(err, "UEContextModificationConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationConfirm")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationFailure{}
		return report, aper.OperationError(err, "UEContextModificationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationFailure")
}

// NewResetTypeS1Interface constructs a checked complete value.
func NewResetTypeS1Interface(v s00.ResetAll, options ...aper.BuildOption) (ResetType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	value := BridgeNewResetTypeS1InterfaceLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	return value, aper.OperationError(nil, "ResetTypeS1Interface")
}

// NewResetTypePartOfS1Interface constructs a checked complete value.
func NewResetTypePartOfS1Interface(v UEAssociatedLogicalS1ConnectionListRes, options ...aper.BuildOption) (ResetType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	value := BridgeNewResetTypePartOfS1InterfaceLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	return value, aper.OperationError(nil, "ResetTypePartOfS1Interface")
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

type ResetIEValue struct {
	id           s00.ProtocolIEID
	received     aper.WireSpan
	replay       aper.Snapshot
	opaque       aper.OpaqueOpenType
	isOpaque     bool
	rowCause     *s14.Cause
	rowResetType *ResetType
}

func (v ResetIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(92):
		return v.rowResetType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ResetIEValue and reports whether the opaque alternative is selected.
func (v *ResetIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ResetIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs"}}
}
func (ResetIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(92):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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
	case s00.ProtocolIEID(91):
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

// AsCause returns the selected Cause value of ResetIEValue and reports whether that alternative is active.
func (v *ResetIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsResetType returns the selected ResetType value of ResetIEValue and reports whether that alternative is active.
func (v *ResetIEValue) AsResetType() (*ResetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(92) || v.rowResetType == nil {
		return nil, false
	}
	return v.rowResetType, true
}
func (v ResetIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResetIEValue, error) {
	out := ResetIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(92):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ResetType
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ResetType:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetType")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowResetType = &value
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
func (v ResetIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ResetIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "ResetIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(92):
		if v.rowResetType == nil {
			return nil, fmt.Errorf("%s missing value", "ResetIEs.id-ResetType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowResetType.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResetIEValue:", v.id)
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

// Opaque returns the retained opaque open value of UEAssociatedLogicalS1ConnectionItemResIEValue and reports whether the opaque alternative is selected.
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

// AsUEAssociatedLogicalS1ConnectionItem returns the selected UEAssociatedLogicalS1ConnectionItem value of UEAssociatedLogicalS1ConnectionItemResIEValue and reports whether that alternative is active.
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

// Opaque returns the retained opaque open value of UEAssociatedLogicalS1ConnectionItemResAckIEValue and reports whether the opaque alternative is selected.
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

// AsUEAssociatedLogicalS1ConnectionItem returns the selected UEAssociatedLogicalS1ConnectionItem value of UEAssociatedLogicalS1ConnectionItemResAckIEValue and reports whether that alternative is active.
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

type InitialUEMessageIETable struct{}

func InitialUEMessageIEs() InitialUEMessageIETable { return InitialUEMessageIETable{} }

// ID returns the ASN.1 object-set identity of InitialUEMessageIETable.
func (InitialUEMessageIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InitialUEMessageIETable.
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

// ENBUES1APID returns the typed binding for the ENBUES1APID row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) ENBUES1APID() s35.InitialUEMessageENBUES1APIDIEBinding {
	return func() s35.InitialUEMessageENBUES1APIDIEBinding {
		sealed := s35.InitialUEMessageENBUES1APIDIEBinding{}
		*s35.BridgeInitialUEMessageENBUES1APIDIEBindingFieldInfo(&sealed) = t.infoENBUES1APID()
		*s35.BridgeInitialUEMessageENBUES1APIDIEBindingFieldCodec(&sealed) = func() s00.ENBUES1APIDValueCodec {
			sealed := s00.ENBUES1APIDValueCodec{}
			*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
			*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ENBUES1APID")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(8), raw)
				if err != nil {
					var empty s00.ENBUES1APID
					return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
				}
				value, ok := decoded.AsENBUES1APID()
				if !ok {
					var empty s00.ENBUES1APID
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-eNB-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
					*s35.BridgeInitialUEMessageIEValueFieldRowENBUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageENBUES1APIDIEBindingFieldInject(&sealed) = func(value s00.ENBUES1APID) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(8)
				*s35.BridgeInitialUEMessageIEValueFieldRowENBUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageENBUES1APIDIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-NAS-PDU"}}}
}

// NASPDU returns the typed binding for the NASPDU row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) NASPDU() s35.InitialUEMessageNASPDUIEBinding {
	return func() s35.InitialUEMessageNASPDUIEBinding {
		sealed := s35.InitialUEMessageNASPDUIEBinding{}
		*s35.BridgeInitialUEMessageNASPDUIEBindingFieldInfo(&sealed) = t.infoNASPDU()
		*s35.BridgeInitialUEMessageNASPDUIEBindingFieldCodec(&sealed) = func() s01.NASPDUValueCodec {
			sealed := s01.NASPDUValueCodec{}
			*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
			*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.NASPDU
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NASPDU")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(26), raw)
				if err != nil {
					var empty s00.NASPDU
					return empty, runtime.WrapDecodePath(err, "NASPDU")
				}
				value, ok := decoded.AsNASPDU()
				if !ok {
					var empty s00.NASPDU
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-NAS-PDU: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
					*s35.BridgeInitialUEMessageIEValueFieldRowNASPDU(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageNASPDUIEBindingFieldInject(&sealed) = func(value s00.NASPDU) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(26)
				*s35.BridgeInitialUEMessageIEValueFieldRowNASPDU(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageNASPDUIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) TAI() s35.InitialUEMessageTAIIEBinding {
	return func() s35.InitialUEMessageTAIIEBinding {
		sealed := s35.InitialUEMessageTAIIEBinding{}
		*s35.BridgeInitialUEMessageTAIIEBindingFieldInfo(&sealed) = t.infoTAI()
		*s35.BridgeInitialUEMessageTAIIEBindingFieldCodec(&sealed) = func() s32.TAIValueCodec {
			sealed := s32.TAIValueCodec{}
			*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
			*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s32.TAI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TAI")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(67), raw)
				if err != nil {
					var empty s32.TAI
					return empty, runtime.WrapDecodePath(err, "TAI")
				}
				value, ok := decoded.AsTAI()
				if !ok {
					var empty s32.TAI
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-TAI: no selected value")
				}
				return *value, nil
			}
			*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s32.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
					*s35.BridgeInitialUEMessageIEValueFieldRowTAI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s32.BridgeTAIValueCodecFieldCapture(&sealed) = func(v s32.TAI, options aper.DecodeState) (s32.TAI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s32.BridgeCaptureS1APTAI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,
					false)
				return v, root
			}
			*s32.BridgeTAIValueCodecFieldCompare(&sealed) = func(v s32.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s32.BridgeCompareS1APTAI(&v, &s)
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
		}()
		*s35.BridgeInitialUEMessageTAIIEBindingFieldInject(&sealed) = func(value s32.TAI) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(67)
				*s35.BridgeInitialUEMessageIEValueFieldRowTAI(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageTAIIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s32.TAI, bool) { return value.AsTAI() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) EUTRANCGI() s35.InitialUEMessageEUTRANCGIIEBinding {
	return func() s35.InitialUEMessageEUTRANCGIIEBinding {
		sealed := s35.InitialUEMessageEUTRANCGIIEBinding{}
		*s35.BridgeInitialUEMessageEUTRANCGIIEBindingFieldInfo(&sealed) = t.infoEUTRANCGI()
		*s35.BridgeInitialUEMessageEUTRANCGIIEBindingFieldCodec(&sealed) = func() s18.EUTRANCGIValueCodec {
			sealed := s18.EUTRANCGIValueCodec{}
			*s18.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
			*s18.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s17.EUTRANCGI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EUTRANCGI")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(100), raw)
				if err != nil {
					var empty s17.EUTRANCGI
					return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
				}
				value, ok := decoded.AsEUTRANCGI()
				if !ok {
					var empty s17.EUTRANCGI
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-EUTRAN-CGI: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
					*s35.BridgeInitialUEMessageIEValueFieldRowEUTRANCGI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s18.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s17.EUTRANCGI, options aper.DecodeState) (s17.EUTRANCGI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.
					Begin()
				s17.BridgeCaptureS1APEUTRANCGI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s18.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s17.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s17.BridgeCompareS1APEUTRANCGI(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s18.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s35.BridgeInitialUEMessageEUTRANCGIIEBindingFieldInject(&sealed) = func(value s17.EUTRANCGI) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(100)
				*s35.BridgeInitialUEMessageIEValueFieldRowEUTRANCGI(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageEUTRANCGIIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoRRCEstablishmentCause() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(134), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RRC-Establishment-Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-RRC-Establishment-Cause"}}}
}

// RRCEstablishmentCause returns the typed binding for the RRCEstablishmentCause row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) RRCEstablishmentCause() s35.InitialUEMessageRRCEstablishmentCauseIEBinding {
	return func() s35.InitialUEMessageRRCEstablishmentCauseIEBinding {
		sealed := s35.InitialUEMessageRRCEstablishmentCauseIEBinding{}
		*s35.BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldInfo(&sealed) = t.infoRRCEstablishmentCause()
		*s35.BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldCodec(&sealed) = func() s01.RRCEstablishmentCauseValueCodec {
			sealed := s01.RRCEstablishmentCauseValueCodec{}
			*s01.BridgeRRCEstablishmentCauseValueCodecFieldPath(&sealed) = "RRCEstablishmentCause"
			*s01.BridgeRRCEstablishmentCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RRCEstablishmentCause, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.RRCEstablishmentCause
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("RRCEstablishmentCause")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(134), raw)
				if err != nil {
					var empty s00.RRCEstablishmentCause
					return empty, runtime.WrapDecodePath(err, "RRCEstablishmentCause")
				}
				value, ok := decoded.AsRRCEstablishmentCause()
				if !ok {
					var empty s00.RRCEstablishmentCause
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-RRC-Establishment-Cause: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeRRCEstablishmentCauseValueCodecFieldEncode(&sealed) = func(value s00.RRCEstablishmentCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(134)
					*s35.BridgeInitialUEMessageIEValueFieldRowRRCEstablishmentCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldInject(&sealed) = func(value s00.RRCEstablishmentCause) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(134)
				*s35.BridgeInitialUEMessageIEValueFieldRowRRCEstablishmentCause(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageRRCEstablishmentCauseIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.RRCEstablishmentCause, bool) {
			return value.AsRRCEstablishmentCause()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-S-TMSI"}}}
}

// STMSI returns the typed binding for the STMSI row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) STMSI() s35.InitialUEMessageSTMSIIEBinding {
	return func() s35.InitialUEMessageSTMSIIEBinding {
		sealed := s35.InitialUEMessageSTMSIIEBinding{}
		*s35.BridgeInitialUEMessageSTMSIIEBindingFieldInfo(&sealed) = t.infoSTMSI()
		*s35.BridgeInitialUEMessageSTMSIIEBindingFieldCodec(&sealed) = func() s28.STMSIValueCodec {
			sealed := s28.STMSIValueCodec{}
			*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
			*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.STMSI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s28.STMSI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("STMSI")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(96), raw)
				if err != nil {
					var empty s28.STMSI
					return empty, runtime.WrapDecodePath(err, "STMSI")
				}
				value, ok := decoded.AsSTMSI()
				if !ok {
					var empty s28.STMSI
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-S-TMSI: no selected value")
				}
				return *value, nil
			}
			*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s28.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
					*s35.BridgeInitialUEMessageIEValueFieldRowSTMSI(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s28.BridgeSTMSIValueCodecFieldCapture(&sealed) = func(v s28.STMSI, options aper.DecodeState) (s28.STMSI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s28.BridgeCaptureS1APSTMSI(&v, &s)
				var root aper.Snapshot
				s.End(f,
					&root, false)
				return v, root
			}
			*s28.BridgeSTMSIValueCodecFieldCompare(&sealed) = func(v s28.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s28.BridgeCompareS1APSTMSI(&v, &s)
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
		}()
		*s35.BridgeInitialUEMessageSTMSIIEBindingFieldInject(&sealed) = func(value s28.STMSI) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(96)
				*s35.BridgeInitialUEMessageIEValueFieldRowSTMSI(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageSTMSIIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s28.STMSI, bool) { return value.AsSTMSI() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CSG-Id"}}}
}

// CSGId returns the typed binding for the CSGId row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) CSGId() s35.InitialUEMessageCSGIdIEBinding {
	return func() s35.InitialUEMessageCSGIdIEBinding {
		sealed := s35.InitialUEMessageCSGIdIEBinding{}
		*s35.BridgeInitialUEMessageCSGIdIEBindingFieldInfo(&sealed) = t.infoCSGId()
		*s35.BridgeInitialUEMessageCSGIdIEBindingFieldCodec(&sealed) = func() s00.CSGIdValueCodec {
			sealed := s00.CSGIdValueCodec{}
			*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
			*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSGId
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGId")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(127), raw)
				if err != nil {
					var empty s00.CSGId
					return empty, runtime.WrapDecodePath(err, "CSGId")
				}
				value, ok := decoded.AsCSGId()
				if !ok {
					var empty s00.CSGId
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CSG-Id: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
					*s35.BridgeInitialUEMessageIEValueFieldRowCSGId(&sealed) = &value
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
		*s35.BridgeInitialUEMessageCSGIdIEBindingFieldInject(&sealed) = func(value s00.CSGId) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s35.BridgeInitialUEMessageIEValueFieldRowCSGId(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageCSGIdIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoGUMMEIID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(75), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GUMMEI-ID"}}}
}

// GUMMEIID returns the typed binding for the GUMMEIID row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) GUMMEIID() s35.InitialUEMessageGUMMEIIEBinding {
	return func() s35.InitialUEMessageGUMMEIIEBinding {
		sealed := s35.InitialUEMessageGUMMEIIEBinding{}
		*s35.BridgeInitialUEMessageGUMMEIIEBindingFieldInfo(&sealed) = t.infoGUMMEIID()
		*s35.BridgeInitialUEMessageGUMMEIIEBindingFieldCodec(&sealed) = func() s18.GUMMEIValueCodec {
			sealed := s18.GUMMEIValueCodec{}
			*s18.BridgeGUMMEIValueCodecFieldPath(&sealed) = "GUMMEI"
			*s18.BridgeGUMMEIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.GUMMEI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("GUMMEI")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(75), raw)
				if err != nil {
					var empty s18.GUMMEI
					return empty, runtime.WrapDecodePath(err, "GUMMEI")
				}
				value, ok := decoded.AsGUMMEIID()
				if !ok {
					var empty s18.GUMMEI
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GUMMEI-ID: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeGUMMEIValueCodecFieldEncode(&sealed) = func(value s18.GUMMEI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
					*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIID(&sealed) = &value
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
		*s35.BridgeInitialUEMessageGUMMEIIEBindingFieldInject(&sealed) = func(value s18.GUMMEI) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIID(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageGUMMEIIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s18.GUMMEI, bool) { return value.AsGUMMEIID() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoCellAccessMode() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(145), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellAccessMode"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CellAccessMode"}}}
}

// CellAccessMode returns the typed binding for the CellAccessMode row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) CellAccessMode() s35.InitialUEMessageCellAccessModeIEBinding {
	return func() s35.InitialUEMessageCellAccessModeIEBinding {
		sealed := s35.InitialUEMessageCellAccessModeIEBinding{}
		*s35.BridgeInitialUEMessageCellAccessModeIEBindingFieldInfo(&sealed) = t.infoCellAccessMode()
		*s35.BridgeInitialUEMessageCellAccessModeIEBindingFieldCodec(&sealed) = func() s00.CellAccessModeValueCodec {
			sealed := s00.CellAccessModeValueCodec{}
			*s00.BridgeCellAccessModeValueCodecFieldPath(&sealed) = "CellAccessMode"
			*s00.BridgeCellAccessModeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellAccessMode, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CellAccessMode
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CellAccessMode")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(145), raw)
				if err != nil {
					var empty s00.CellAccessMode
					return empty, runtime.WrapDecodePath(err, "CellAccessMode")
				}
				value, ok := decoded.AsCellAccessMode()
				if !ok {
					var empty s00.CellAccessMode
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CellAccessMode: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCellAccessModeValueCodecFieldEncode(&sealed) = func(value s00.CellAccessMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
					*s35.BridgeInitialUEMessageIEValueFieldRowCellAccessMode(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageCellAccessModeIEBindingFieldInject(&sealed) = func(value s00.CellAccessMode) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(145)
				*s35.BridgeInitialUEMessageIEValueFieldRowCellAccessMode(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageCellAccessModeIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.CellAccessMode, bool) { return value.AsCellAccessMode() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(155), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GW-TransportLayerAddress"}}}
}

// GWTransportLayerAddress returns the typed binding for the GWTransportLayerAddress row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) GWTransportLayerAddress() s35.InitialUEMessageTransportLayerAddressIEBinding {
	return func() s35.InitialUEMessageTransportLayerAddressIEBinding {
		sealed := s35.InitialUEMessageTransportLayerAddressIEBinding{}
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInfo(&sealed) = t.infoGWTransportLayerAddress()
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldCodec(&sealed) = func() s02.TransportLayerAddressValueCodec {
			sealed := s02.TransportLayerAddressValueCodec{}
			*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
			*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(155), raw)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
				}
				value, ok := decoded.AsGWTransportLayerAddress()
				if !ok {
					var empty s00.TransportLayerAddress
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GW-TransportLayerAddress: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
					*s35.BridgeInitialUEMessageIEValueFieldRowGWTransportLayerAddress(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInject(&sealed) = func(value s00.TransportLayerAddress) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(155)
				*s35.BridgeInitialUEMessageIEValueFieldRowGWTransportLayerAddress(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsGWTransportLayerAddress()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoRelayNodeIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(160), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RelayNode-Indicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-RelayNode-Indicator"}}}
}

// RelayNodeIndicator returns the typed binding for the RelayNodeIndicator row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) RelayNodeIndicator() s35.InitialUEMessageRelayNodeIndicatorIEBinding {
	return func() s35.InitialUEMessageRelayNodeIndicatorIEBinding {
		sealed := s35.InitialUEMessageRelayNodeIndicatorIEBinding{}
		*s35.BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldInfo(&sealed) = t.infoRelayNodeIndicator()
		*s35.BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldCodec(&sealed) = func() s01.RelayNodeIndicatorValueCodec {
			sealed := s01.RelayNodeIndicatorValueCodec{}
			*s01.BridgeRelayNodeIndicatorValueCodecFieldPath(&sealed) = "RelayNodeIndicator"
			*s01.BridgeRelayNodeIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RelayNodeIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.RelayNodeIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("RelayNodeIndicator")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(160), raw)
				if err != nil {
					var empty s00.RelayNodeIndicator
					return empty, runtime.WrapDecodePath(err, "RelayNodeIndicator")
				}
				value, ok := decoded.AsRelayNodeIndicator()
				if !ok {
					var empty s00.RelayNodeIndicator
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-RelayNode-Indicator: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeRelayNodeIndicatorValueCodecFieldEncode(&sealed) = func(value s00.RelayNodeIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(160)
					*s35.BridgeInitialUEMessageIEValueFieldRowRelayNodeIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldInject(&sealed) = func(value s00.RelayNodeIndicator) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(160)
				*s35.BridgeInitialUEMessageIEValueFieldRowRelayNodeIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageRelayNodeIndicatorIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.RelayNodeIndicator, bool) {
			return value.AsRelayNodeIndicator()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoGUMMEIType() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(170), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEIType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-GUMMEIType"}}}
}

// GUMMEIType returns the typed binding for the GUMMEIType row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) GUMMEIType() s35.InitialUEMessageGUMMEITypeIEBinding {
	return func() s35.InitialUEMessageGUMMEITypeIEBinding {
		sealed := s35.InitialUEMessageGUMMEITypeIEBinding{}
		*s35.BridgeInitialUEMessageGUMMEITypeIEBindingFieldInfo(&sealed) = t.infoGUMMEIType()
		*s35.BridgeInitialUEMessageGUMMEITypeIEBindingFieldCodec(&sealed) = func() s00.GUMMEITypeValueCodec {
			sealed := s00.GUMMEITypeValueCodec{}
			*s00.BridgeGUMMEITypeValueCodecFieldPath(&sealed) = "GUMMEIType"
			*s00.BridgeGUMMEITypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GUMMEIType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.GUMMEIType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("GUMMEIType")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(170), raw)
				if err != nil {
					var empty s00.GUMMEIType
					return empty, runtime.WrapDecodePath(err, "GUMMEIType")
				}
				value, ok := decoded.AsGUMMEIType()
				if !ok {
					var empty s00.GUMMEIType
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-GUMMEIType: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeGUMMEITypeValueCodecFieldEncode(&sealed) = func(value s00.GUMMEIType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(170)
					*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIType(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageGUMMEITypeIEBindingFieldInject(&sealed) = func(value s00.GUMMEIType) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(170)
				*s35.BridgeInitialUEMessageIEValueFieldRowGUMMEIType(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageGUMMEITypeIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.GUMMEIType, bool) { return value.AsGUMMEIType() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-Tunnel-Information-for-BBF"}}}
}

// TunnelInformationForBBF returns the typed binding for the TunnelInformationForBBF row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) TunnelInformationForBBF() s35.InitialUEMessageTunnelInformationIEBinding {
	return func() s35.InitialUEMessageTunnelInformationIEBinding {
		sealed := s35.InitialUEMessageTunnelInformationIEBinding{}
		*s35.BridgeInitialUEMessageTunnelInformationIEBindingFieldInfo(&sealed) = t.infoTunnelInformationForBBF()
		*s35.BridgeInitialUEMessageTunnelInformationIEBindingFieldCodec(&sealed) = func() s35.TunnelInformationValueCodec {
			sealed := s35.TunnelInformationValueCodec{}
			*s35.BridgeTunnelInformationValueCodecFieldPath(&sealed) = "TunnelInformation"
			*s35.BridgeTunnelInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.TunnelInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s35.TunnelInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TunnelInformation")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(176), raw)
				if err != nil {
					var empty s35.TunnelInformation
					return empty, runtime.WrapDecodePath(err, "TunnelInformation")
				}
				value, ok := decoded.AsTunnelInformationForBBF()
				if !ok {
					var empty s35.TunnelInformation
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-Tunnel-Information-for-BBF: no selected value")
				}
				return *value, nil
			}
			*s35.BridgeTunnelInformationValueCodecFieldEncode(&sealed) = func(value s35.TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
					*s35.BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s35.BridgeTunnelInformationValueCodecFieldCapture(&sealed) = func(v s35.TunnelInformation, options aper.DecodeState) (s35.TunnelInformation, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s35.BridgeCaptureS1APTunnelInformation(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s35.BridgeTunnelInformationValueCodecFieldCompare(&sealed) = func(v s35.TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s35.BridgeCompareS1APTunnelInformation(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s35.BridgeTunnelInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s35.BridgeInitialUEMessageTunnelInformationIEBindingFieldInject(&sealed) = func(value s35.TunnelInformation) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(176)
				*s35.BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageTunnelInformationIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s35.TunnelInformation, bool) {
			return value.AsTunnelInformationForBBF()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoSIPTOLGWTransportLayerAddress() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(184), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TransportLayerAddress"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-SIPTO-L-GW-TransportLayerAddress"}}}
}

// SIPTOLGWTransportLayerAddress returns the typed binding for the SIPTOLGWTransportLayerAddress row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) SIPTOLGWTransportLayerAddress() s35.InitialUEMessageTransportLayerAddressIEBinding {
	return func() s35.InitialUEMessageTransportLayerAddressIEBinding {
		sealed := s35.InitialUEMessageTransportLayerAddressIEBinding{}
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInfo(&sealed) = t.infoSIPTOLGWTransportLayerAddress()
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldCodec(&sealed) = func() s02.TransportLayerAddressValueCodec {
			sealed := s02.TransportLayerAddressValueCodec{}
			*s02.BridgeTransportLayerAddressValueCodecFieldPath(&sealed) = "TransportLayerAddress"
			*s02.BridgeTransportLayerAddressValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TransportLayerAddress, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TransportLayerAddress")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(184), raw)
				if err != nil {
					var empty s00.TransportLayerAddress
					return empty, runtime.WrapDecodePath(err, "TransportLayerAddress")
				}
				value, ok := decoded.AsSIPTOLGWTransportLayerAddress()
				if !ok {
					var empty s00.TransportLayerAddress
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-SIPTO-L-GW-TransportLayerAddress: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&sealed) = func(value s00.TransportLayerAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
					*s35.BridgeInitialUEMessageIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldInject(&sealed) = func(value s00.TransportLayerAddress) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(184)
				*s35.BridgeInitialUEMessageIEValueFieldRowSIPTOLGWTransportLayerAddress(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageTransportLayerAddressIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.TransportLayerAddress, bool) {
			return value.AsSIPTOLGWTransportLayerAddress()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoLHNID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(186), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LHN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-LHN-ID"}}}
}

// LHNID returns the typed binding for the LHNID row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) LHNID() s35.InitialUEMessageLHNIDIEBinding {
	return func() s35.InitialUEMessageLHNIDIEBinding {
		sealed := s35.InitialUEMessageLHNIDIEBinding{}
		*s35.BridgeInitialUEMessageLHNIDIEBindingFieldInfo(&sealed) = t.infoLHNID()
		*s35.BridgeInitialUEMessageLHNIDIEBindingFieldCodec(&sealed) = func() s01.LHNIDValueCodec {
			sealed := s01.LHNIDValueCodec{}
			*s01.BridgeLHNIDValueCodecFieldPath(&sealed) = "LHNID"
			*s01.BridgeLHNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LHNID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.LHNID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("LHNID")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(186), raw)
				if err != nil {
					var empty s00.LHNID
					return empty, runtime.WrapDecodePath(err, "LHNID")
				}
				value, ok := decoded.AsLHNID()
				if !ok {
					var empty s00.LHNID
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-LHN-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeLHNIDValueCodecFieldEncode(&sealed) = func(value s00.LHNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
					*s35.BridgeInitialUEMessageIEValueFieldRowLHNID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageLHNIDIEBindingFieldInject(&sealed) = func(value s00.LHNID) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(186)
				*s35.BridgeInitialUEMessageIEValueFieldRowLHNID(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageLHNIDIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.LHNID, bool) { return value.AsLHNID() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoMMEGroupID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(223), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-Group-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-MME-Group-ID"}}}
}

// MMEGroupID returns the typed binding for the MMEGroupID row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) MMEGroupID() s35.InitialUEMessageMMEGroupIDIEBinding {
	return func() s35.InitialUEMessageMMEGroupIDIEBinding {
		sealed := s35.InitialUEMessageMMEGroupIDIEBinding{}
		*s35.BridgeInitialUEMessageMMEGroupIDIEBindingFieldInfo(&sealed) = t.infoMMEGroupID()
		*s35.BridgeInitialUEMessageMMEGroupIDIEBindingFieldCodec(&sealed) = func() s01.MMEGroupIDValueCodec {
			sealed := s01.MMEGroupIDValueCodec{}
			*s01.BridgeMMEGroupIDValueCodecFieldPath(&sealed) = "MMEGroupID"
			*s01.BridgeMMEGroupIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEGroupID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEGroupID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEGroupID")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(223), raw)
				if err != nil {
					var empty s00.MMEGroupID
					return empty, runtime.WrapDecodePath(err, "MMEGroupID")
				}
				value, ok := decoded.AsMMEGroupID()
				if !ok {
					var empty s00.MMEGroupID
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-MME-Group-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEGroupIDValueCodecFieldEncode(&sealed) = func(value s00.MMEGroupID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
					*s35.BridgeInitialUEMessageIEValueFieldRowMMEGroupID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageMMEGroupIDIEBindingFieldInject(&sealed) = func(value s00.MMEGroupID) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(223)
				*s35.BridgeInitialUEMessageIEValueFieldRowMMEGroupID(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageMMEGroupIDIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.MMEGroupID, bool) { return value.AsMMEGroupID() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoUEUsageType() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(230), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Usage-Type"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-UE-Usage-Type"}}}
}

// UEUsageType returns the typed binding for the UEUsageType row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) UEUsageType() s35.InitialUEMessageUEUsageTypeIEBinding {
	return func() s35.InitialUEMessageUEUsageTypeIEBinding {
		sealed := s35.InitialUEMessageUEUsageTypeIEBinding{}
		*s35.BridgeInitialUEMessageUEUsageTypeIEBindingFieldInfo(&sealed) = t.infoUEUsageType()
		*s35.BridgeInitialUEMessageUEUsageTypeIEBindingFieldCodec(&sealed) = func() s02.UEUsageTypeValueCodec {
			sealed := s02.UEUsageTypeValueCodec{}
			*s02.BridgeUEUsageTypeValueCodecFieldPath(&sealed) = "UEUsageType"
			*s02.BridgeUEUsageTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUsageType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UEUsageType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEUsageType")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(230), raw)
				if err != nil {
					var empty s00.UEUsageType
					return empty, runtime.WrapDecodePath(err, "UEUsageType")
				}
				value, ok := decoded.AsUEUsageType()
				if !ok {
					var empty s00.UEUsageType
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-UE-Usage-Type: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUEUsageTypeValueCodecFieldEncode(&sealed) = func(value s00.UEUsageType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
					*s35.BridgeInitialUEMessageIEValueFieldRowUEUsageType(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageUEUsageTypeIEBindingFieldInject(&sealed) = func(value s00.UEUsageType) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(230)
				*s35.BridgeInitialUEMessageIEValueFieldRowUEUsageType(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageUEUsageTypeIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.UEUsageType, bool) { return value.AsUEUsageType() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoCEModeBSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(242), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-mode-B-SupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CE-mode-B-SupportIndicator"}}}
}

// CEModeBSupportIndicator returns the typed binding for the CEModeBSupportIndicator row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) CEModeBSupportIndicator() s35.InitialUEMessageCEModeBSupportIndicatorIEBinding {
	return func() s35.InitialUEMessageCEModeBSupportIndicatorIEBinding {
		sealed := s35.InitialUEMessageCEModeBSupportIndicatorIEBinding{}
		*s35.BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldInfo(&sealed) = t.infoCEModeBSupportIndicator()
		*s35.BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldCodec(&sealed) = func() s00.CEModeBSupportIndicatorValueCodec {
			sealed := s00.CEModeBSupportIndicatorValueCodec{}
			*s00.BridgeCEModeBSupportIndicatorValueCodecFieldPath(&sealed) = "CEModeBSupportIndicator"
			*s00.BridgeCEModeBSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBSupportIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CEModeBSupportIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CEModeBSupportIndicator")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(242), raw)
				if err != nil {
					var empty s00.CEModeBSupportIndicator
					return empty, runtime.WrapDecodePath(err, "CEModeBSupportIndicator")
				}
				value, ok := decoded.AsCEModeBSupportIndicator()
				if !ok {
					var empty s00.CEModeBSupportIndicator
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CE-mode-B-SupportIndicator: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCEModeBSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CEModeBSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
					*s35.BridgeInitialUEMessageIEValueFieldRowCEModeBSupportIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldInject(&sealed) = func(value s00.CEModeBSupportIndicator) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(242)
				*s35.BridgeInitialUEMessageIEValueFieldRowCEModeBSupportIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageCEModeBSupportIndicatorIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.CEModeBSupportIndicator, bool) {
			return value.AsCEModeBSupportIndicator()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoDCNID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(246), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DCN-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-DCN-ID"}}}
}

// DCNID returns the typed binding for the DCNID row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) DCNID() s35.InitialUEMessageDCNIDIEBinding {
	return func() s35.InitialUEMessageDCNIDIEBinding {
		sealed := s35.InitialUEMessageDCNIDIEBinding{}
		*s35.BridgeInitialUEMessageDCNIDIEBindingFieldInfo(&sealed) = t.infoDCNID()
		*s35.BridgeInitialUEMessageDCNIDIEBindingFieldCodec(&sealed) = func() s00.DCNIDValueCodec {
			sealed := s00.DCNIDValueCodec{}
			*s00.BridgeDCNIDValueCodecFieldPath(&sealed) = "DCNID"
			*s00.BridgeDCNIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DCNID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.DCNID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("DCNID")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(246), raw)
				if err != nil {
					var empty s00.DCNID
					return empty, runtime.WrapDecodePath(err, "DCNID")
				}
				value, ok := decoded.AsDCNID()
				if !ok {
					var empty s00.DCNID
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-DCN-ID: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeDCNIDValueCodecFieldEncode(&sealed) = func(value s00.DCNID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(246)
					*s35.BridgeInitialUEMessageIEValueFieldRowDCNID(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageDCNIDIEBindingFieldInject(&sealed) = func(value s00.DCNID) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(246)
				*s35.BridgeInitialUEMessageIEValueFieldRowDCNID(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageDCNIDIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.DCNID, bool) { return value.AsDCNID() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoCoverageLevel() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(250), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Coverage-Level"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-Coverage-Level"}}}
}

// CoverageLevel returns the typed binding for the CoverageLevel row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) CoverageLevel() s35.InitialUEMessageCoverageLevelIEBinding {
	return func() s35.InitialUEMessageCoverageLevelIEBinding {
		sealed := s35.InitialUEMessageCoverageLevelIEBinding{}
		*s35.BridgeInitialUEMessageCoverageLevelIEBindingFieldInfo(&sealed) = t.infoCoverageLevel()
		*s35.BridgeInitialUEMessageCoverageLevelIEBindingFieldCodec(&sealed) = func() s00.CoverageLevelValueCodec {
			sealed := s00.CoverageLevelValueCodec{}
			*s00.BridgeCoverageLevelValueCodecFieldPath(&sealed) = "CoverageLevel"
			*s00.BridgeCoverageLevelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoverageLevel, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CoverageLevel
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CoverageLevel")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(250), raw)
				if err != nil {
					var empty s00.CoverageLevel
					return empty, runtime.WrapDecodePath(err, "CoverageLevel")
				}
				value, ok := decoded.AsCoverageLevel()
				if !ok {
					var empty s00.CoverageLevel
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-Coverage-Level: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCoverageLevelValueCodecFieldEncode(&sealed) = func(value s00.CoverageLevel, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(250)
					*s35.BridgeInitialUEMessageIEValueFieldRowCoverageLevel(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageCoverageLevelIEBindingFieldInject(&sealed) = func(value s00.CoverageLevel) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(250)
				*s35.BridgeInitialUEMessageIEValueFieldRowCoverageLevel(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageCoverageLevelIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.CoverageLevel, bool) { return value.AsCoverageLevel() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoUEApplicationLayerMeasurementCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(263), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-Application-Layer-Measurement-Capability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-UE-Application-Layer-Measurement-Capability"}}}
}

// UEApplicationLayerMeasurementCapability returns the typed binding for the UEApplicationLayerMeasurementCapability row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) UEApplicationLayerMeasurementCapability() s35.InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding {
	return func() s35.InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding {
		sealed := s35.InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding{}
		*s35.BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldInfo(&sealed) = t.infoUEApplicationLayerMeasurementCapability()
		*s35.BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldCodec(&sealed) = func() s02.UEApplicationLayerMeasurementCapabilityValueCodec {
			sealed := s02.UEApplicationLayerMeasurementCapabilityValueCodec{}
			*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldPath(&sealed) = "UEApplicationLayerMeasurementCapability"
			*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UEApplicationLayerMeasurementCapability
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEApplicationLayerMeasurementCapability")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(263), raw)
				if err != nil {
					var empty s00.UEApplicationLayerMeasurementCapability
					return empty, runtime.WrapDecodePath(err, "UEApplicationLayerMeasurementCapability")
				}
				value, ok := decoded.AsUEApplicationLayerMeasurementCapability()
				if !ok {
					var empty s00.UEApplicationLayerMeasurementCapability
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-UE-Application-Layer-Measurement-Capability: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UEApplicationLayerMeasurementCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
					*s35.BridgeInitialUEMessageIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldInject(&sealed) = func(value s00.UEApplicationLayerMeasurementCapability) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(263)
				*s35.BridgeInitialUEMessageIEValueFieldRowUEApplicationLayerMeasurementCapability(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageUEApplicationLayerMeasurementCapabilityIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.UEApplicationLayerMeasurementCapability, bool) {
			return value.AsUEApplicationLayerMeasurementCapability()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoEDTSession() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(281), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EDT-Session"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-EDT-Session"}}}
}

// EDTSession returns the typed binding for the EDTSession row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) EDTSession() s35.InitialUEMessageEDTSessionIEBinding {
	return func() s35.InitialUEMessageEDTSessionIEBinding {
		sealed := s35.InitialUEMessageEDTSessionIEBinding{}
		*s35.BridgeInitialUEMessageEDTSessionIEBindingFieldInfo(&sealed) = t.infoEDTSession()
		*s35.BridgeInitialUEMessageEDTSessionIEBindingFieldCodec(&sealed) = func() s00.EDTSessionValueCodec {
			sealed := s00.EDTSessionValueCodec{}
			*s00.BridgeEDTSessionValueCodecFieldPath(&sealed) = "EDTSession"
			*s00.BridgeEDTSessionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EDTSession, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EDTSession
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EDTSession")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(281), raw)
				if err != nil {
					var empty s00.EDTSession
					return empty, runtime.WrapDecodePath(err, "EDTSession")
				}
				value, ok := decoded.AsEDTSession()
				if !ok {
					var empty s00.EDTSession
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-EDT-Session: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEDTSessionValueCodecFieldEncode(&sealed) = func(value s00.EDTSession, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(281)
					*s35.BridgeInitialUEMessageIEValueFieldRowEDTSession(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageEDTSessionIEBindingFieldInject(&sealed) = func(value s00.EDTSession) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(281)
				*s35.BridgeInitialUEMessageIEValueFieldRowEDTSession(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageEDTSessionIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.EDTSession, bool) { return value.AsEDTSession() }
		return sealed
	}()
}
func (InitialUEMessageIETable) infoIABNodeIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(302), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Node-Indication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-IAB-Node-Indication"}}}
}

// IABNodeIndication returns the typed binding for the IABNodeIndication row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) IABNodeIndication() s35.InitialUEMessageIABNodeIndicationIEBinding {
	return func() s35.InitialUEMessageIABNodeIndicationIEBinding {
		sealed := s35.InitialUEMessageIABNodeIndicationIEBinding{}
		*s35.BridgeInitialUEMessageIABNodeIndicationIEBindingFieldInfo(&sealed) = t.infoIABNodeIndication()
		*s35.BridgeInitialUEMessageIABNodeIndicationIEBindingFieldCodec(&sealed) = func() s01.IABNodeIndicationValueCodec {
			sealed := s01.IABNodeIndicationValueCodec{}
			*s01.BridgeIABNodeIndicationValueCodecFieldPath(&sealed) = "IABNodeIndication"
			*s01.BridgeIABNodeIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABNodeIndication, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.IABNodeIndication
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("IABNodeIndication")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(302), raw)
				if err != nil {
					var empty s00.IABNodeIndication
					return empty, runtime.WrapDecodePath(err, "IABNodeIndication")
				}
				value, ok := decoded.AsIABNodeIndication()
				if !ok {
					var empty s00.IABNodeIndication
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-IAB-Node-Indication: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeIABNodeIndicationValueCodecFieldEncode(&sealed) = func(value s00.IABNodeIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(302)
					*s35.BridgeInitialUEMessageIEValueFieldRowIABNodeIndication(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageIABNodeIndicationIEBindingFieldInject(&sealed) = func(value s00.IABNodeIndication) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(302)
				*s35.BridgeInitialUEMessageIEValueFieldRowIABNodeIndication(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageIABNodeIndicationIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.IABNodeIndication, bool) {
			return value.AsIABNodeIndication()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) LTENTNTAIInformation() s35.InitialUEMessageLTENTNTAIInformationIEBinding {
	return func() s35.InitialUEMessageLTENTNTAIInformationIEBinding {
		sealed := s35.InitialUEMessageLTENTNTAIInformationIEBinding{}
		*s35.BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldInfo(&sealed) = t.infoLTENTNTAIInformation()
		*s35.BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldCodec(&sealed) = func() s18.LTENTNTAIInformationValueCodec {
			sealed := s18.LTENTNTAIInformationValueCodec{}
			*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
			*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.LTENTNTAIInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(339), raw)
				if err != nil {
					var empty s18.LTENTNTAIInformation
					return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
				}
				value, ok := decoded.AsLTENTNTAIInformation()
				if !ok {
					var empty s18.LTENTNTAIInformation
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-LTE-NTN-TAI-Information: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
					*s35.BridgeInitialUEMessageIEValueFieldRowLTENTNTAIInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldInject(&sealed) = func(value s18.LTENTNTAIInformation) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(339)
				*s35.BridgeInitialUEMessageIEValueFieldRowLTENTNTAIInformation(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageLTENTNTAIInformationIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}
		return sealed
	}()
}
func (InitialUEMessageIETable) infoCoarseUELocationRequested() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialUEMessageIEs().ID(), ID: s00.ProtocolIEID(353), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocationRequested"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialUEMessage-IEs", Row: "id-CoarseUELocationRequested"}}}
}

// CoarseUELocationRequested returns the typed binding for the CoarseUELocationRequested row of InitialUEMessageIETable.
func (t InitialUEMessageIETable) CoarseUELocationRequested() s35.InitialUEMessageCoarseUELocationRequestedIEBinding {
	return func() s35.InitialUEMessageCoarseUELocationRequestedIEBinding {
		sealed := s35.InitialUEMessageCoarseUELocationRequestedIEBinding{}
		*s35.BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldInfo(&sealed) = t.infoCoarseUELocationRequested()
		*s35.BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldCodec(&sealed) = func() s00.CoarseUELocationRequestedValueCodec {
			sealed := s00.CoarseUELocationRequestedValueCodec{}
			*s00.BridgeCoarseUELocationRequestedValueCodecFieldPath(&sealed) = "CoarseUELocationRequested"
			*s00.BridgeCoarseUELocationRequestedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocationRequested, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CoarseUELocationRequested
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CoarseUELocationRequested")
				var zero s35.InitialUEMessageIEValue
				decoded, err := s35.BridgeInitialUEMessageIEValueMethodDecode(zero, s00.ProtocolIEID(353), raw)
				if err != nil {
					var empty s00.CoarseUELocationRequested
					return empty, runtime.WrapDecodePath(err, "CoarseUELocationRequested")
				}
				value, ok := decoded.AsCoarseUELocationRequested()
				if !ok {
					var empty s00.CoarseUELocationRequested
					return empty, fmt.Errorf("binding InitialUEMessage-IEs.id-CoarseUELocationRequested: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCoarseUELocationRequestedValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocationRequested, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s35.BridgeInitialUEMessageIEValueMethodEncodeFresh((func() s35.InitialUEMessageIEValue {
					sealed := s35.InitialUEMessageIEValue{}
					*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(353)
					*s35.BridgeInitialUEMessageIEValueFieldRowCoarseUELocationRequested(&sealed) = &value
					return sealed
				}()), fresh, budget)
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
		}()
		*s35.BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldInject(&sealed) = func(value s00.CoarseUELocationRequested) s35.InitialUEMessageIEValue {
			return func() s35.InitialUEMessageIEValue {
				sealed := s35.InitialUEMessageIEValue{}
				*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = s00.ProtocolIEID(353)
				*s35.BridgeInitialUEMessageIEValueFieldRowCoarseUELocationRequested(&sealed) = &value
				return sealed
			}()
		}
		*s35.BridgeInitialUEMessageCoarseUELocationRequestedIEBindingFieldGet(&sealed) = func(value *s35.InitialUEMessageIEValue) (*s00.CoarseUELocationRequested, bool) {
			return value.AsCoarseUELocationRequested()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InitialUEMessageIETable.
func (t InitialUEMessageIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s35.InitialUEMessageIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(134):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-RRC-Establishment-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(96):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(75):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEI-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(145):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellAccessMode requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(155):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(160):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-RelayNode-Indicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(170):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEIType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(176):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-Tunnel-Information-for-BBF requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(184):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-SIPTO-L-GW-TransportLayerAddress requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(186):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-LHN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(223):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-Group-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(230):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Usage-Type requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(242):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-mode-B-SupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(246):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-DCN-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(250):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-Coverage-Level requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(263):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-Application-Layer-Measurement-Capability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(281):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-EDT-Session requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(302):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Node-Indication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(353):
		return s35.InitialUEMessageIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocationRequested requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s35.InitialUEMessageIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s35.InitialUEMessageIEField{}, aper.OperationError(err, "Opaque")
		}
		return s35.InitialUEMessageIEField{Id: id, Criticality: criticality, Value: func() s35.InitialUEMessageIEValue {
			sealed := s35.InitialUEMessageIEValue{}
			*s35.BridgeInitialUEMessageIEValueFieldId(&sealed) = id
			*s35.BridgeInitialUEMessageIEValueFieldOpaque(&sealed) = opaque
			*s35.BridgeInitialUEMessageIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type ResetIETable struct{}

func ResetIEs() ResetIETable { return ResetIETable{} }

// ID returns the ASN.1 object-set identity of ResetIETable.
func (ResetIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ResetIETable.
func (ResetIETable) Table() s00.ResetIEValueIETable {
	return func() s00.ResetIEValueIETable {
		sealed := s00.ResetIEValueIETable{}
		*s00.BridgeResetIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ResetIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of ResetIETable.
func (t ResetIETable) Cause() ResetCauseIEBinding {
	return ResetCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero ResetIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding ResetIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s14.Cause) ResetIEValue { return ResetIEValue{id: s00.ProtocolIEID(2), rowCause: &value} }, get: func(value *ResetIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (ResetIETable) infoResetType() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetIEs().ID(), ID: s00.ProtocolIEID(92), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs", Row: "id-ResetType"}}}
}

// ResetType returns the typed binding for the ResetType row of ResetIETable.
func (t ResetIETable) ResetType() ResetResetTypeIEBinding {
	return ResetResetTypeIEBinding{info: t.infoResetType(), codec: ResetTypeValueCodec{path: "ResetType",
		decode: func(data []byte, options aper.DecodeState) (ResetType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ResetType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ResetType")
			var zero ResetIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(92), raw)
			if err != nil {
				var empty ResetType
				return empty, runtime.WrapDecodePath(err, "ResetType")
			}
			value, ok := decoded.AsResetType()
			if !ok {
				var empty ResetType
				return empty, fmt.Errorf("binding ResetIEs.id-ResetType: no selected value")
			}
			return *value, nil
		},
		encode: func(value ResetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetIEValue{id: s00.ProtocolIEID(92), rowResetType: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ResetType, options aper.DecodeState) (ResetType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			BridgeCaptureS1APResetType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ResetType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APResetType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResetType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ResetType) ResetIEValue {
		return ResetIEValue{id: s00.ProtocolIEID(92), rowResetType: &value}
	}, get: func(value *ResetIEValue) (*ResetType, bool) { return value.AsResetType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ResetIETable.
func (t ResetIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResetIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ResetIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(92):
		return ResetIEField{}, aper.OperationError(fmt.Errorf("known IE id-ResetType requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResetIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResetIEField{}, aper.OperationError(err, "Opaque")
		}
		return ResetIEField{Id: id, Criticality: criticality, Value: ResetIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEAssociatedLogicalS1ConnectionItemResTable struct{}

func UEAssociatedLogicalS1ConnectionItemRes() UEAssociatedLogicalS1ConnectionItemResTable {
	return UEAssociatedLogicalS1ConnectionItemResTable{}
}

// ID returns the ASN.1 object-set identity of UEAssociatedLogicalS1ConnectionItemResTable.
func (UEAssociatedLogicalS1ConnectionItemResTable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemRes"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEAssociatedLogicalS1ConnectionItemResTable.
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

// UEAssociatedLogicalS1ConnectionItem returns the typed binding for the UEAssociatedLogicalS1ConnectionItem row of UEAssociatedLogicalS1ConnectionItemResTable.
func (t UEAssociatedLogicalS1ConnectionItemResTable) UEAssociatedLogicalS1ConnectionItem() UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding {
	return UEAssociatedLogicalS1ConnectionItemResUEAssociatedLogicalS1ConnectionItemIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionItem(), codec: UEAssociatedLogicalS1ConnectionItemValueCodec{path: "UEAssociatedLogicalS1ConnectionItem",
		decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAssociatedLogicalS1ConnectionItem")
			var zero UEAssociatedLogicalS1ConnectionItemResIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(91), raw)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItem")
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

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEAssociatedLogicalS1ConnectionItemResTable.
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

// ID returns the ASN.1 object-set identity of UEAssociatedLogicalS1ConnectionItemResAckTable.
func (UEAssociatedLogicalS1ConnectionItemResAckTable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionItemResAck"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEAssociatedLogicalS1ConnectionItemResAckTable.
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

// UEAssociatedLogicalS1ConnectionItem returns the typed binding for the UEAssociatedLogicalS1ConnectionItem row of UEAssociatedLogicalS1ConnectionItemResAckTable.
func (t UEAssociatedLogicalS1ConnectionItemResAckTable) UEAssociatedLogicalS1ConnectionItem() UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding {
	return UEAssociatedLogicalS1ConnectionItemResAckUEAssociatedLogicalS1ConnectionItemIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionItem(), codec: UEAssociatedLogicalS1ConnectionItemValueCodec{path: "UEAssociatedLogicalS1ConnectionItem",
		decode: func(data []byte, options aper.DecodeState) (UEAssociatedLogicalS1ConnectionItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAssociatedLogicalS1ConnectionItem")
			var zero UEAssociatedLogicalS1ConnectionItemResAckIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(91), raw)
			if err != nil {
				var empty UEAssociatedLogicalS1ConnectionItem
				return empty, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionItem")
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

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEAssociatedLogicalS1ConnectionItemResAckTable.
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
func LHNIDCodec() s01.LHNIDValueCodec { return s35.HandoverNotifyIEs().LHNID().Codec() }

// MMEGroupIDCodec binds the complete APER value type.
func MMEGroupIDCodec() s01.MMEGroupIDValueCodec { return InitialUEMessageIEs().MMEGroupID().Codec() }

// NotifySourceeNBCodec binds the complete APER value type.
func NotifySourceeNBCodec() s01.NotifySourceeNBValueCodec {
	return s35.HandoverNotifyIEs().NotifySourceeNB().Codec()
}

// RRCEstablishmentCauseCodec binds the complete APER value type.
func RRCEstablishmentCauseCodec() s01.RRCEstablishmentCauseValueCodec {
	return InitialUEMessageIEs().RRCEstablishmentCause().Codec()
}

// RelayNodeIndicatorCodec binds the complete APER value type.
func RelayNodeIndicatorCodec() s01.RelayNodeIndicatorValueCodec {
	return InitialUEMessageIEs().RelayNodeIndicator().Codec()
}

// ResetTypeCodec binds the complete APER value type.
func ResetTypeCodec() ResetTypeValueCodec { return ResetIEs().ResetType().Codec() }

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
func BridgeResetAPERValueFieldContext(v *ResetAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeResetAPERValueFieldReceived(v *ResetAPERValue) *aper.WireSpan         { return &v.received }
func BridgeResetAPERValueFieldReplay(v *ResetAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeResetAPERValueFieldWithoutReplay(v *ResetAPERValue) *bool             { return &v.withoutReplay }
func BridgeResetCauseIEBindingFieldCodec(v *ResetCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeResetCauseIEBindingFieldGet(v *ResetCauseIEBinding) *func(*ResetIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeResetCauseIEBindingFieldInfo(v *ResetCauseIEBinding) *s00.FieldInfo { return &v.info }
func BridgeResetCauseIEBindingFieldInject(v *ResetCauseIEBinding) *func(s14.Cause) ResetIEValue {
	return &v.inject
}
func BridgeResetFieldExtCount(v *Reset) *int64                       { return &v.extCount }
func BridgeResetFieldExtData(v *Reset) *[][]byte                     { return &v.extData }
func BridgeResetFieldExtOrigin(v *Reset) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgeResetFieldExtPresent(v *Reset) *[]bool                    { return &v.extPresent }
func BridgeResetFieldExtWire(v *Reset) *[]aper.WireSpan              { return &v.extWire }
func BridgeResetFieldPerExtPadding(v *Reset) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgeResetFieldPerPadding(v *Reset) *aper.FinalPadding         { return &v.perPadding }
func BridgeResetFieldProtocolIEsIndef(v *Reset) *bool                { return &v.protocolIEsIndef }
func BridgeResetFieldReceived(v *Reset) *bool                        { return &v.received }
func BridgeResetFieldReceivedAbsolute(v *Reset) *bool                { return &v.receivedAbsolute }
func BridgeResetFieldReceivedBytes(v *Reset) *aper.WireSpan          { return &v.receivedBytes }
func BridgeResetFieldReceivedLocation(v *Reset) *aper.Location       { return &v.receivedLocation }
func BridgeResetFieldReplay(v *Reset) *aper.Snapshot                 { return &v.replay }
func BridgeResetFieldStream(v *Reset) *aper.WireSpan                 { return &v.stream }
func BridgeResetFieldWithoutReplay(v *Reset) *bool                   { return &v.withoutReplay }
func BridgeResetIEContainerAPERValueFieldContext(v *ResetIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEContainerAPERValueFieldReceived(v *ResetIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEContainerAPERValueFieldReplay(v *ResetIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEContainerAPERValueFieldWithoutReplay(v *ResetIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEContainerValueCodecFieldCapture(v *ResetIEContainerValueCodec) *func(ResetIEContainer, aper.DecodeState) (ResetIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEContainerValueCodecFieldCompare(v *ResetIEContainerValueCodec) *func(ResetIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEContainerValueCodecFieldContext(v *ResetIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEContainerValueCodecFieldDecode(v *ResetIEContainerValueCodec) *func([]byte, aper.DecodeState) (ResetIEContainer, error) {
	return &v.decode
}
func BridgeResetIEContainerValueCodecFieldEncode(v *ResetIEContainerValueCodec) *func(ResetIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEContainerValueCodecFieldPath(v *ResetIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEContainerValueCodecMethodEncodeBudgetValue(v ResetIEContainerValueCodec, a0 ResetIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEContainerValueCodecMethodEncodeChanged(v ResetIEContainerValueCodec, a0 ResetIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEFieldAPERValueFieldContext(v *ResetIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEFieldAPERValueFieldReceived(v *ResetIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEFieldAPERValueFieldReplay(v *ResetIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEFieldAPERValueFieldWithoutReplay(v *ResetIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEFieldFieldReceived(v *ResetIEField) *aper.CompletePadding { return &v.received }
func BridgeResetIEFieldFieldReplay(v *ResetIEField) *aper.Snapshot          { return &v.replay }
func BridgeResetIEFieldFieldStream(v *ResetIEField) *aper.WireSpan          { return &v.stream }
func BridgeResetIEFieldFieldWithoutReplay(v *ResetIEField) *bool            { return &v.withoutReplay }
func BridgeResetIEFieldMethodMarshalAPERTo(v *ResetIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetIEFieldMethodUnmarshalAPERFrom(v *ResetIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetIEFieldValueCodecFieldCapture(v *ResetIEFieldValueCodec) *func(ResetIEField, aper.DecodeState) (ResetIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEFieldValueCodecFieldCompare(v *ResetIEFieldValueCodec) *func(ResetIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEFieldValueCodecFieldContext(v *ResetIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEFieldValueCodecFieldDecode(v *ResetIEFieldValueCodec) *func([]byte, aper.DecodeState) (ResetIEField, error) {
	return &v.decode
}
func BridgeResetIEFieldValueCodecFieldEncode(v *ResetIEFieldValueCodec) *func(ResetIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEFieldValueCodecFieldPath(v *ResetIEFieldValueCodec) *aper.Path { return &v.path }
func BridgeResetIEFieldValueCodecMethodEncodeBudgetValue(v ResetIEFieldValueCodec, a0 ResetIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEFieldValueCodecMethodEncodeChanged(v ResetIEFieldValueCodec, a0 ResetIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIETableMethodInfoCause(v ResetIETable) s00.FieldInfo     { return v.infoCause() }
func BridgeResetIETableMethodInfoResetType(v ResetIETable) s00.FieldInfo { return v.infoResetType() }
func BridgeResetIEValueERABIEContainerListAPERValueFieldContext(v *ResetIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldReceived(v *ResetIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldReplay(v *ResetIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldCapture(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldCompare(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldContext(v *ResetIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldDecode(v *ResetIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldEncode(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldPath(v *ResetIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueERABIEContainerListValueCodec, a0 ResetIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueERABIEContainerListValueCodec, a0 ResetIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEValueFieldId(v *ResetIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgeResetIEValueFieldIsOpaque(v *ResetIEValue) *bool              { return &v.isOpaque }
func BridgeResetIEValueFieldOpaque(v *ResetIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeResetIEValueFieldReceived(v *ResetIEValue) *aper.WireSpan     { return &v.received }
func BridgeResetIEValueFieldReplay(v *ResetIEValue) *aper.Snapshot       { return &v.replay }
func BridgeResetIEValueFieldRowCause(v *ResetIEValue) **s14.Cause        { return &v.rowCause }
func BridgeResetIEValueFieldRowResetType(v *ResetIEValue) **ResetType    { return &v.rowResetType }
func BridgeResetIEValueMethodCaptureSemantics(v ResetIEValue, a0 aper.SemanticCapture) ResetIEValue {
	return v.captureSemantics(a0)
}
func BridgeResetIEValueMethodCompareSemantics(v ResetIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResetIEValueMethodDecode(v ResetIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResetIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeResetIEValueMethodEncode(v ResetIEValue) ([]byte, error) { return v.encode() }
func BridgeResetIEValueMethodEncodeFresh(v ResetIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResetIEValueMethodMatchesID(v ResetIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeResetIEValueMethodReason(v ResetIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResetIEValueMethodRule(v ResetIEValue) aper.SourceRule { return v.rule() }
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueProtocolErrorIEContainerListValueCodec, a0 ResetIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueProtocolErrorIEContainerListValueCodec, a0 ResetIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldContext(v *ResetIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldReceived(v *ResetIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldReplay(v *ResetIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldCapture(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldCompare(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldContext(v *ResetIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldDecode(v *ResetIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldEncode(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldPath(v *ResetIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueProtocolIEContainerListValueCodec, a0 ResetIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueProtocolIEContainerListValueCodec, a0 ResetIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetMethodMarshalAPERBudget(v *Reset, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResetMethodMarshalAPERBudgetValue(v *Reset, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeResetMethodMarshalAPERChanged(v *Reset, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERChangedValue(v *Reset, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERLegacy(v *Reset) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeResetMethodMarshalAPERNewValue(v *Reset, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeResetMethodMarshalAPERPlanned(v *Reset, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERTo(v *Reset, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetMethodUnmarshalAPERFrom(v *Reset, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetMethodUnmarshalAPERLegacy(v *Reset, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResetMethodUnmarshalAPERWithOptions(v *Reset, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResetResetTypeIEBindingFieldCodec(v *ResetResetTypeIEBinding) *ResetTypeValueCodec {
	return &v.codec
}
func BridgeResetResetTypeIEBindingFieldGet(v *ResetResetTypeIEBinding) *func(*ResetIEValue) (*ResetType, bool) {
	return &v.get
}
func BridgeResetResetTypeIEBindingFieldInfo(v *ResetResetTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResetResetTypeIEBindingFieldInject(v *ResetResetTypeIEBinding) *func(ResetType) ResetIEValue {
	return &v.inject
}
func BridgeResetTypeAPERValueFieldContext(v *ResetTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetTypeAPERValueFieldReceived(v *ResetTypeAPERValue) *aper.WireSpan { return &v.received }
func BridgeResetTypeAPERValueFieldReplay(v *ResetTypeAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeResetTypeAPERValueFieldWithoutReplay(v *ResetTypeAPERValue) *bool     { return &v.withoutReplay }
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
func BridgeResetTypeValueCodecFieldCapture(v *ResetTypeValueCodec) *func(ResetType, aper.DecodeState) (ResetType, aper.Snapshot) {
	return &v.capture
}
func BridgeResetTypeValueCodecFieldCompare(v *ResetTypeValueCodec) *func(ResetType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetTypeValueCodecFieldContext(v *ResetTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetTypeValueCodecFieldDecode(v *ResetTypeValueCodec) *func([]byte, aper.DecodeState) (ResetType, error) {
	return &v.decode
}
func BridgeResetTypeValueCodecFieldEncode(v *ResetTypeValueCodec) *func(ResetType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetTypeValueCodecFieldPath(v *ResetTypeValueCodec) *aper.Path { return &v.path }
func BridgeResetTypeValueCodecMethodEncodeBudgetValue(v ResetTypeValueCodec, a0 ResetType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetTypeValueCodecMethodEncodeChanged(v ResetTypeValueCodec, a0 ResetType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetValueCodecFieldCapture(v *ResetValueCodec) *func(Reset, aper.DecodeState) (Reset, aper.Snapshot) {
	return &v.capture
}
func BridgeResetValueCodecFieldCompare(v *ResetValueCodec) *func(Reset, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetValueCodecFieldContext(v *ResetValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeResetValueCodecFieldDecode(v *ResetValueCodec) *func([]byte, aper.DecodeState) (Reset, error) {
	return &v.decode
}
func BridgeResetValueCodecFieldEncode(v *ResetValueCodec) *func(Reset, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetValueCodecFieldPath(v *ResetValueCodec) *aper.Path { return &v.path }
func BridgeResetValueCodecMethodEncodeBudgetValue(v ResetValueCodec, a0 Reset, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetValueCodecMethodEncodeChanged(v ResetValueCodec, a0 Reset, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeUECapabilityInfoIndicationAPERValueFieldContext(v *UECapabilityInfoIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoIndicationAPERValueFieldReceived(v *UECapabilityInfoIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUECapabilityInfoIndicationAPERValueFieldReplay(v *UECapabilityInfoIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUECapabilityInfoIndicationAPERValueFieldWithoutReplay(v *UECapabilityInfoIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUECapabilityInfoIndicationFieldExtCount(v *UECapabilityInfoIndication) *int64 {
	return &v.extCount
}
func BridgeUECapabilityInfoIndicationFieldExtData(v *UECapabilityInfoIndication) *[][]byte {
	return &v.extData
}
func BridgeUECapabilityInfoIndicationFieldExtOrigin(v *UECapabilityInfoIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUECapabilityInfoIndicationFieldExtPresent(v *UECapabilityInfoIndication) *[]bool {
	return &v.extPresent
}
func BridgeUECapabilityInfoIndicationFieldExtWire(v *UECapabilityInfoIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUECapabilityInfoIndicationFieldPerExtPadding(v *UECapabilityInfoIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUECapabilityInfoIndicationFieldPerPadding(v *UECapabilityInfoIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUECapabilityInfoIndicationFieldProtocolIEsIndef(v *UECapabilityInfoIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeUECapabilityInfoIndicationFieldReceived(v *UECapabilityInfoIndication) *bool {
	return &v.received
}
func BridgeUECapabilityInfoIndicationFieldReceivedAbsolute(v *UECapabilityInfoIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeUECapabilityInfoIndicationFieldReceivedBytes(v *UECapabilityInfoIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUECapabilityInfoIndicationFieldReceivedLocation(v *UECapabilityInfoIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeUECapabilityInfoIndicationFieldReplay(v *UECapabilityInfoIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeUECapabilityInfoIndicationFieldStream(v *UECapabilityInfoIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeUECapabilityInfoIndicationFieldWithoutReplay(v *UECapabilityInfoIndication) *bool {
	return &v.withoutReplay
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERBudgetValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERChanged(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERChangedValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERLegacy(v *UECapabilityInfoIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERNewValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERPlanned(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERTo(v *UECapabilityInfoIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERFrom(v *UECapabilityInfoIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERLegacy(v *UECapabilityInfoIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERWithOptions(v *UECapabilityInfoIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUECapabilityInfoIndicationValueCodecFieldCapture(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, aper.DecodeState) (UECapabilityInfoIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUECapabilityInfoIndicationValueCodecFieldCompare(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUECapabilityInfoIndicationValueCodecFieldContext(v *UECapabilityInfoIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoIndicationValueCodecFieldDecode(v *UECapabilityInfoIndicationValueCodec) *func([]byte, aper.DecodeState) (UECapabilityInfoIndication, error) {
	return &v.decode
}
func BridgeUECapabilityInfoIndicationValueCodecFieldEncode(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUECapabilityInfoIndicationValueCodecFieldPath(v *UECapabilityInfoIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUECapabilityInfoIndicationValueCodecMethodEncodeBudgetValue(v UECapabilityInfoIndicationValueCodec, a0 UECapabilityInfoIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationValueCodecMethodEncodeChanged(v UECapabilityInfoIndicationValueCodec, a0 UECapabilityInfoIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmAPERValueFieldContext(v *UEContextModificationConfirmAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmAPERValueFieldReceived(v *UEContextModificationConfirmAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmAPERValueFieldReplay(v *UEContextModificationConfirmAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmAPERValueFieldWithoutReplay(v *UEContextModificationConfirmAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmFieldExtCount(v *UEContextModificationConfirm) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationConfirmFieldExtData(v *UEContextModificationConfirm) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationConfirmFieldExtOrigin(v *UEContextModificationConfirm) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationConfirmFieldExtPresent(v *UEContextModificationConfirm) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationConfirmFieldExtWire(v *UEContextModificationConfirm) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationConfirmFieldPerExtPadding(v *UEContextModificationConfirm) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationConfirmFieldPerPadding(v *UEContextModificationConfirm) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationConfirmFieldProtocolIEsIndef(v *UEContextModificationConfirm) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationConfirmFieldReceived(v *UEContextModificationConfirm) *bool {
	return &v.received
}
func BridgeUEContextModificationConfirmFieldReceivedAbsolute(v *UEContextModificationConfirm) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationConfirmFieldReceivedBytes(v *UEContextModificationConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationConfirmFieldReceivedLocation(v *UEContextModificationConfirm) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationConfirmFieldReplay(v *UEContextModificationConfirm) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmFieldStream(v *UEContextModificationConfirm) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationConfirmFieldWithoutReplay(v *UEContextModificationConfirm) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERBudgetValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERChanged(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERChangedValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERLegacy(v *UEContextModificationConfirm) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationConfirmMethodMarshalAPERNewValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERPlanned(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERTo(v *UEContextModificationConfirm, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERFrom(v *UEContextModificationConfirm, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERLegacy(v *UEContextModificationConfirm, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERWithOptions(v *UEContextModificationConfirm, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationConfirmValueCodecFieldCapture(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, aper.DecodeState) (UEContextModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmValueCodecFieldCompare(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmValueCodecFieldContext(v *UEContextModificationConfirmValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmValueCodecFieldDecode(v *UEContextModificationConfirmValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirm, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmValueCodecFieldEncode(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmValueCodecFieldPath(v *UEContextModificationConfirmValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmValueCodec, a0 UEContextModificationConfirm, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmValueCodecMethodEncodeChanged(v UEContextModificationConfirmValueCodec, a0 UEContextModificationConfirm, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureAPERValueFieldContext(v *UEContextModificationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureAPERValueFieldReceived(v *UEContextModificationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureAPERValueFieldReplay(v *UEContextModificationFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureAPERValueFieldWithoutReplay(v *UEContextModificationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureFieldExtCount(v *UEContextModificationFailure) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationFailureFieldExtData(v *UEContextModificationFailure) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationFailureFieldExtOrigin(v *UEContextModificationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationFailureFieldExtPresent(v *UEContextModificationFailure) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationFailureFieldExtWire(v *UEContextModificationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationFailureFieldPerExtPadding(v *UEContextModificationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationFailureFieldPerPadding(v *UEContextModificationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationFailureFieldProtocolIEsIndef(v *UEContextModificationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationFailureFieldReceived(v *UEContextModificationFailure) *bool {
	return &v.received
}
func BridgeUEContextModificationFailureFieldReceivedAbsolute(v *UEContextModificationFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationFailureFieldReceivedBytes(v *UEContextModificationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationFailureFieldReceivedLocation(v *UEContextModificationFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationFailureFieldReplay(v *UEContextModificationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureFieldStream(v *UEContextModificationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationFailureFieldWithoutReplay(v *UEContextModificationFailure) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureMethodMarshalAPERBudget(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERBudgetValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERChanged(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERChangedValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERLegacy(v *UEContextModificationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationFailureMethodMarshalAPERNewValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERPlanned(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERTo(v *UEContextModificationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERFrom(v *UEContextModificationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERLegacy(v *UEContextModificationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERWithOptions(v *UEContextModificationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationFailureValueCodecFieldCapture(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, aper.DecodeState) (UEContextModificationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureValueCodecFieldCompare(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureValueCodecFieldContext(v *UEContextModificationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureValueCodecFieldDecode(v *UEContextModificationFailureValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailure, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureValueCodecFieldEncode(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureValueCodecFieldPath(v *UEContextModificationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureValueCodec, a0 UEContextModificationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureValueCodecMethodEncodeChanged(v UEContextModificationFailureValueCodec, a0 UEContextModificationFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResetIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 92:
		if value, ok := v.AsResetType(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEAssociatedLogicalS1ConnectionItemResAckIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 91:
		if value, ok := v.AsUEAssociatedLogicalS1ConnectionItem(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEAssociatedLogicalS1ConnectionItemResIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 91:
		if value, ok := v.AsUEAssociatedLogicalS1ConnectionItem(); ok {
			return value, true
		}
	}
	return nil, false
}
