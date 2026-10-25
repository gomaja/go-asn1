// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s34 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s34

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverRequiredIEContainer is ProtocolIE-Container {{HandoverRequiredIEs}} of TS 36.413: a list of HandoverRequiredIEField values.
type HandoverRequiredIEContainer []HandoverRequiredIEField

// HandoverRequiredIEField is ProtocolIE-Field {{HandoverRequiredIEs}} of TS 36.413: an information element field.
type HandoverRequiredIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverRequiredIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEField) WithoutReplay() HandoverRequiredIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverRequiredIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverRequiredIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverRequiredIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequiredIEField{}
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
	var zero HandoverRequiredIEValue

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

// ENBDirectInformationTransferIEContainer is ProtocolIE-Container {{ENBDirectInformationTransferIEs}} of TS 36.413: a list of ENBDirectInformationTransferIEField values.
type ENBDirectInformationTransferIEContainer []ENBDirectInformationTransferIEField

// ENBDirectInformationTransferIEField is ProtocolIE-Field {{ENBDirectInformationTransferIEs}} of TS 36.413: an information element field.
type ENBDirectInformationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBDirectInformationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEField) WithoutReplay() ENBDirectInformationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBDirectInformationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBDirectInformationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBDirectInformationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBDirectInformationTransferIEField{}
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
	var zero ENBDirectInformationTransferIEValue

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

// MMEDirectInformationTransferIEContainer is ProtocolIE-Container {{MMEDirectInformationTransferIEs}} of TS 36.413: a list of MMEDirectInformationTransferIEField values.
type MMEDirectInformationTransferIEContainer []MMEDirectInformationTransferIEField

// MMEDirectInformationTransferIEField is ProtocolIE-Field {{MMEDirectInformationTransferIEs}} of TS 36.413: an information element field.
type MMEDirectInformationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEDirectInformationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEField) WithoutReplay() MMEDirectInformationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEDirectInformationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEDirectInformationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEDirectInformationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEDirectInformationTransferIEField{}
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
	var zero MMEDirectInformationTransferIEValue

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
func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(v *ENBDirectInformationTransferIEContainer, s *aper.SemanticCapture) {
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
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainer(v *ENBDirectInformationTransferIEContainer, s *aper.SemanticComparison) {
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
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(v *MMEDirectInformationTransferIEContainer, s *aper.SemanticCapture) {
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
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainer(v *MMEDirectInformationTransferIEContainer, s *aper.SemanticComparison) {
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
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TAIItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TAIItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTAIItemIEValueCaptureS1APProtocolIESingleContainer(v *TAIItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTAIItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeTAIItemIEValueCompareS1APProtocolIESingleContainer(v *TAIItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTAIItemIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TargetNgRanNodeIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TargetNgRanNodeIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TargetRNCIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TargetRNCIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TargeteNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TargeteNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{TAIItemIEs}} of TS 36.413: a single information element field.
type TAIItemIEValueProtocolIESingleContainer = TAIItemIEField

// ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding binds InterSystemInformationTransferType to the ENBDirectInformationTransferIEs object set of TS 36.413.
type ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding struct {
	info   s00.FieldInfo
	codec  InterSystemInformationTransferTypeValueCodec
	inject func(InterSystemInformationTransferType,

	) ENBDirectInformationTransferIEValue

	get func(*ENBDirectInformationTransferIEValue,

	) (*InterSystemInformationTransferType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Codec() InterSystemInformationTransferTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) New(value InterSystemInformationTransferType,

) (ENBDirectInformationTransferIEField, error) {
	if b.inject == nil {
		return ENBDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBDirectInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBDirectInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Get(field *ENBDirectInformationTransferIEField) (*InterSystemInformationTransferType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InterSystemInformationTransferTypeValueCodec is the concrete ValueCodec[InterSystemInformationTransferType].
type InterSystemInformationTransferTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InterSystemInformationTransferType,

		error)
	encode func(InterSystemInformationTransferType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InterSystemInformationTransferType, aper.DecodeState,

	) (InterSystemInformationTransferType, aper.Snapshot,

	)
	compare func(InterSystemInformationTransferType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterSystemInformationTransferTypeValueCodec) New(value InterSystemInformationTransferType,

) (InterSystemInformationTransferTypeAPERValue, error) {
	if c.encode == nil {
		return InterSystemInformationTransferTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterSystemInformationTransferTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterSystemInformationTransferTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterSystemInformationTransferTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterSystemInformationTransferTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterSystemInformationTransferTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterSystemInformationTransferTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterSystemInformationTransferTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterSystemInformationTransferTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterSystemInformationTransferTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterSystemInformationTransferTypeValueCodec) EncodeAPER(value InterSystemInformationTransferTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterSystemInformationTransferTypeValueCodec) encodeBudgetValue(value InterSystemInformationTransferType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterSystemInformationTransferTypeValueCodec) encodeChanged(value InterSystemInformationTransferType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredMMEUES1APIDIEBinding) Get(field *HandoverRequiredIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredENBUES1APIDIEBinding binds ENBUES1APID to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredENBUES1APIDIEBinding) Get(field *HandoverRequiredIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredHandoverTypeIEBinding binds HandoverType to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredHandoverTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.HandoverTypeValueCodec
	inject func(s00.HandoverType,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.HandoverType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredHandoverTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredHandoverTypeIEBinding) Codec() s00.HandoverTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredHandoverTypeIEBinding) New(value s00.HandoverType,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeHandoverTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredHandoverTypeIEBinding) Get(field *HandoverRequiredIEField) (*s00.HandoverType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredCauseIEBinding binds Cause to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredCauseIEBinding) New(value s14.Cause,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredCauseIEBinding) Get(field *HandoverRequiredIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredTargetIDIEBinding binds TargetID to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredTargetIDIEBinding struct {
	info   s00.FieldInfo
	codec  TargetIDValueCodec
	inject func(TargetID,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*TargetID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredTargetIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredTargetIDIEBinding) Codec() TargetIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredTargetIDIEBinding) New(value TargetID,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredTargetIDIEBinding) Get(field *HandoverRequiredIEField) (*TargetID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TargetIDValueCodec is the concrete ValueCodec[TargetID].
type TargetIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetID,

		error)
	encode func(TargetID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetID, aper.DecodeState,

	) (TargetID, aper.Snapshot,

	)
	compare func(TargetID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetIDValueCodec) New(value TargetID,

) (TargetIDAPERValue, error) {
	if c.encode == nil {
		return TargetIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetIDValueCodec) EncodeAPER(value TargetIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetIDValueCodec) encodeBudgetValue(value TargetID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetIDValueCodec) encodeChanged(value TargetID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredDirectForwardingPathAvailabilityIEBinding binds DirectForwardingPathAvailability to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredDirectForwardingPathAvailabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DirectForwardingPathAvailabilityValueCodec
	inject func(s00.DirectForwardingPathAvailability,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.DirectForwardingPathAvailability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredDirectForwardingPathAvailabilityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredDirectForwardingPathAvailabilityIEBinding) Codec() s00.DirectForwardingPathAvailabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequiredDirectForwardingPathAvailabilityIEBinding) New(value s00.DirectForwardingPathAvailability,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredDirectForwardingPathAvailabilityIEBinding) Get(field *HandoverRequiredIEField) (*s00.DirectForwardingPathAvailability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredSRVCCHOIndicationIEBinding binds SRVCCHOIndication to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredSRVCCHOIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCHOIndicationValueCodec
	inject func(s00.SRVCCHOIndication,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.SRVCCHOIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) Codec() s01.SRVCCHOIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) New(value s00.SRVCCHOIndication,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCHOIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) Get(field *HandoverRequiredIEField) (*s00.SRVCCHOIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredSourceToTargetTransparentContainerIEBinding binds SourceToTargetTransparentContainer to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredSourceToTargetTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SourceToTargetTransparentContainerValueCodec
	inject func(s00.SourceToTargetTransparentContainer,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.SourceToTargetTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredSourceToTargetTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredSourceToTargetTransparentContainerIEBinding) Codec() s01.SourceToTargetTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequiredSourceToTargetTransparentContainerIEBinding) New(value s00.SourceToTargetTransparentContainer,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredSourceToTargetTransparentContainerIEBinding) Get(field *HandoverRequiredIEField) (*s00.SourceToTargetTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredMSClassmark2IEBinding binds MSClassmark2 to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredMSClassmark2IEBinding struct {
	info   s00.FieldInfo
	codec  s01.MSClassmark2ValueCodec
	inject func(s00.MSClassmark2,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.MSClassmark2,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredMSClassmark2IEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredMSClassmark2IEBinding) Codec() s01.MSClassmark2ValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredMSClassmark2IEBinding) New(value s00.MSClassmark2,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMSClassmark2ValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredMSClassmark2IEBinding) Get(field *HandoverRequiredIEField) (*s00.MSClassmark2,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredMSClassmark3IEBinding binds MSClassmark3 to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredMSClassmark3IEBinding struct {
	info   s00.FieldInfo
	codec  s01.MSClassmark3ValueCodec
	inject func(s00.MSClassmark3,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.MSClassmark3,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredMSClassmark3IEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredMSClassmark3IEBinding) Codec() s01.MSClassmark3ValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredMSClassmark3IEBinding) New(value s00.MSClassmark3,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMSClassmark3ValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredMSClassmark3IEBinding) Get(field *HandoverRequiredIEField) (*s00.MSClassmark3,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredCSGIdIEBinding binds CSGId to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredCSGIdIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGIdValueCodec
	inject func(s00.CSGId,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.CSGId,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredCSGIdIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredCSGIdIEBinding) Codec() s00.CSGIdValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredCSGIdIEBinding) New(value s00.CSGId,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGIdValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredCSGIdIEBinding) Get(field *HandoverRequiredIEField) (*s00.CSGId,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredCellAccessModeIEBinding binds CellAccessMode to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredCellAccessModeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellAccessModeValueCodec
	inject func(s00.CellAccessMode,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.CellAccessMode,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredCellAccessModeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredCellAccessModeIEBinding) Codec() s00.CellAccessModeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequiredCellAccessModeIEBinding) New(value s00.CellAccessMode,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellAccessModeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredCellAccessModeIEBinding) Get(field *HandoverRequiredIEField) (*s00.CellAccessMode,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequiredPSServiceNotAvailableIEBinding binds PSServiceNotAvailable to the HandoverRequiredIEs object set of TS 36.413.
type HandoverRequiredPSServiceNotAvailableIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PSServiceNotAvailableValueCodec
	inject func(s00.PSServiceNotAvailable,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.PSServiceNotAvailable,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredPSServiceNotAvailableIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredPSServiceNotAvailableIEBinding) Codec() s01.PSServiceNotAvailableValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRequiredPSServiceNotAvailableIEBinding) New(value s00.PSServiceNotAvailable,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePSServiceNotAvailableValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredPSServiceNotAvailableIEBinding) Get(field *HandoverRequiredIEField) (*s00.PSServiceNotAvailable,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding binds InterSystemInformationTransferType to the MMEDirectInformationTransferIEs object set of TS 36.413.
type MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding struct {
	info   s00.FieldInfo
	codec  InterSystemInformationTransferTypeValueCodec
	inject func(InterSystemInformationTransferType,

	) MMEDirectInformationTransferIEValue

	get func(*MMEDirectInformationTransferIEValue,

	) (*InterSystemInformationTransferType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Codec() InterSystemInformationTransferTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) New(value InterSystemInformationTransferType,

) (MMEDirectInformationTransferIEField, error) {
	if b.inject == nil {
		return MMEDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEDirectInformationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEDirectInformationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) Get(field *MMEDirectInformationTransferIEField) (*InterSystemInformationTransferType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TAIListValueCodec is the concrete ValueCodec[TAIList].
type TAIListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIList,

		error)
	encode func(TAIList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIList, aper.DecodeState,

	) (TAIList, aper.Snapshot,

	)
	compare func(TAIList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIListValueCodec) New(value TAIList,

) (TAIListAPERValue, error) {
	if c.encode == nil {
		return TAIListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIListValueCodec) EncodeAPER(value TAIListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIListValueCodec) encodeBudgetValue(value TAIList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIListValueCodec) encodeChanged(value TAIList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemTAIItemIEBinding binds TAIItem to the TAIItemIEs object set of TS 36.413.
type TAIItemTAIItemIEBinding struct {
	info   s00.FieldInfo
	codec  TAIItemValueCodec
	inject func(TAIItem,

	) TAIItemIEValue

	get func(*TAIItemIEValue,

	) (*TAIItem,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TAIItemTAIItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TAIItemTAIItemIEBinding) Codec() TAIItemValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TAIItemTAIItemIEBinding) New(value TAIItem,

) (TAIItemIEField, error) {
	if b.inject == nil {
		return TAIItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return TAIItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TAIItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return TAIItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TAIItemTAIItemIEBinding) Get(field *TAIItemIEField) (*TAIItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TAIItemValueCodec is the concrete ValueCodec[TAIItem].
type TAIItemValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItem,

		error)
	encode func(TAIItem,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItem, aper.DecodeState,

	) (TAIItem, aper.Snapshot,

	)
	compare func(TAIItem, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemValueCodec) New(value TAIItem,

) (TAIItemAPERValue, error) {
	if c.encode == nil {
		return TAIItemAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemValueCodec) EncodeAPER(value TAIItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemValueCodec) encodeBudgetValue(value TAIItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemValueCodec) encodeChanged(value TAIItem,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEField is ProtocolIE-Field {{TAIItemIEs}} of TS 36.413: an information element field.
type TAIItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         TAIItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEField) WithoutReplay() TAIItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TAIItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TAIItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *TAIItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIItemIEField{}
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
	var zero TAIItemIEValue

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

// InformationOnRecommendedCellsAndENBsForPagingValueCodec is the concrete ValueCodec[InformationOnRecommendedCellsAndENBsForPaging].
type InformationOnRecommendedCellsAndENBsForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPaging,

		error)
	encode func(InformationOnRecommendedCellsAndENBsForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InformationOnRecommendedCellsAndENBsForPaging, aper.DecodeState,

	) (InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot,

	)
	compare func(InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InformationOnRecommendedCellsAndENBsForPagingValueCodec) New(value InformationOnRecommendedCellsAndENBsForPaging,

) (InformationOnRecommendedCellsAndENBsForPagingAPERValue, error) {
	if c.encode == nil {
		return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InformationOnRecommendedCellsAndENBsForPagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InformationOnRecommendedCellsAndENBsForPagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InformationOnRecommendedCellsAndENBsForPagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InformationOnRecommendedCellsAndENBsForPagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InformationOnRecommendedCellsAndENBsForPagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InformationOnRecommendedCellsAndENBsForPagingValueCodec) EncodeAPER(value InformationOnRecommendedCellsAndENBsForPagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InformationOnRecommendedCellsAndENBsForPagingValueCodec) encodeBudgetValue(value InformationOnRecommendedCellsAndENBsForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InformationOnRecommendedCellsAndENBsForPagingValueCodec) encodeChanged(value InformationOnRecommendedCellsAndENBsForPaging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferValueCodec is the concrete ValueCodec[ENBDirectInformationTransfer].
type ENBDirectInformationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransfer,

		error)
	encode func(ENBDirectInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransfer, aper.DecodeState,

	) (ENBDirectInformationTransfer, aper.Snapshot,

	)
	compare func(ENBDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferValueCodec) New(value ENBDirectInformationTransfer,

) (ENBDirectInformationTransferAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferValueCodec) EncodeAPER(value ENBDirectInformationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferValueCodec) encodeBudgetValue(value ENBDirectInformationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferValueCodec) encodeChanged(value ENBDirectInformationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferValueCodec is the concrete ValueCodec[MMEDirectInformationTransfer].
type MMEDirectInformationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransfer,

		error)
	encode func(MMEDirectInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransfer, aper.DecodeState,

	) (MMEDirectInformationTransfer, aper.Snapshot,

	)
	compare func(MMEDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferValueCodec) New(value MMEDirectInformationTransfer,

) (MMEDirectInformationTransferAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferValueCodec) EncodeAPER(value MMEDirectInformationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferValueCodec) encodeBudgetValue(value MMEDirectInformationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferValueCodec) encodeChanged(value MMEDirectInformationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RIMRoutingAddressValueCodec is the concrete ValueCodec[RIMRoutingAddress].
type RIMRoutingAddressValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RIMRoutingAddress,

		error)
	encode func(RIMRoutingAddress,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RIMRoutingAddress, aper.DecodeState,

	) (RIMRoutingAddress, aper.Snapshot,

	)
	compare func(RIMRoutingAddress, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMRoutingAddressValueCodec) New(value RIMRoutingAddress,

) (RIMRoutingAddressAPERValue, error) {
	if c.encode == nil {
		return RIMRoutingAddressAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RIMRoutingAddressAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RIMRoutingAddressAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RIMRoutingAddressAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMRoutingAddressValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RIMRoutingAddressAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RIMRoutingAddressAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RIMRoutingAddressAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RIMRoutingAddressAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RIMRoutingAddressAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMRoutingAddressValueCodec) EncodeAPER(value RIMRoutingAddressAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RIMRoutingAddressValueCodec) encodeBudgetValue(value RIMRoutingAddress,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMRoutingAddressValueCodec) encodeChanged(value RIMRoutingAddress,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RIMTransferValueCodec is the concrete ValueCodec[RIMTransfer].
type RIMTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RIMTransfer,

		error)
	encode func(RIMTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RIMTransfer, aper.DecodeState,

	) (RIMTransfer, aper.Snapshot,

	)
	compare func(RIMTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMTransferValueCodec) New(value RIMTransfer,

) (RIMTransferAPERValue, error) {
	if c.encode == nil {
		return RIMTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RIMTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RIMTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RIMTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RIMTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RIMTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RIMTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RIMTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RIMTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMTransferValueCodec) EncodeAPER(value RIMTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RIMTransferValueCodec) encodeBudgetValue(value RIMTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMTransferValueCodec) encodeChanged(value RIMTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RecommendedENBsForPagingValueCodec is the concrete ValueCodec[RecommendedENBsForPaging].
type RecommendedENBsForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s33.RecommendedENBsForPaging,

		error)
	encode func(s33.RecommendedENBsForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s33.RecommendedENBsForPaging, aper.DecodeState,

	) (s33.RecommendedENBsForPaging, aper.Snapshot,

	)
	compare func(s33.RecommendedENBsForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBsForPagingValueCodec) New(value s33.RecommendedENBsForPaging,

) (RecommendedENBsForPagingAPERValue, error) {
	if c.encode == nil {
		return RecommendedENBsForPagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RecommendedENBsForPagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RecommendedENBsForPagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RecommendedENBsForPagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RecommendedENBsForPagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RecommendedENBsForPagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RecommendedENBsForPagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RecommendedENBsForPagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RecommendedENBsForPagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RecommendedENBsForPagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RecommendedENBsForPagingValueCodec) EncodeAPER(value RecommendedENBsForPagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RecommendedENBsForPagingValueCodec) encodeBudgetValue(value s33.RecommendedENBsForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBsForPagingValueCodec) encodeChanged(value s33.RecommendedENBsForPaging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetNgRanNodeIDValueCodec is the concrete ValueCodec[TargetNgRanNodeID].
type TargetNgRanNodeIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetNgRanNodeID,

		error)
	encode func(TargetNgRanNodeID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetNgRanNodeID, aper.DecodeState,

	) (TargetNgRanNodeID, aper.Snapshot,

	)
	compare func(TargetNgRanNodeID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetNgRanNodeIDValueCodec) New(value TargetNgRanNodeID,

) (TargetNgRanNodeIDAPERValue, error) {
	if c.encode == nil {
		return TargetNgRanNodeIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetNgRanNodeIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetNgRanNodeIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetNgRanNodeIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetNgRanNodeIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetNgRanNodeIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetNgRanNodeIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetNgRanNodeIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetNgRanNodeIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetNgRanNodeIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetNgRanNodeIDValueCodec) EncodeAPER(value TargetNgRanNodeIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetNgRanNodeIDValueCodec) encodeBudgetValue(value TargetNgRanNodeID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetNgRanNodeIDValueCodec) encodeChanged(value TargetNgRanNodeID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetRNCIDValueCodec is the concrete ValueCodec[TargetRNCID].
type TargetRNCIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargetRNCID,

		error)
	encode func(TargetRNCID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargetRNCID, aper.DecodeState,

	) (TargetRNCID, aper.Snapshot,

	)
	compare func(TargetRNCID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCIDValueCodec) New(value TargetRNCID,

) (TargetRNCIDAPERValue, error) {
	if c.encode == nil {
		return TargetRNCIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetRNCIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetRNCIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetRNCIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetRNCIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetRNCIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetRNCIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetRNCIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetRNCIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetRNCIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetRNCIDValueCodec) EncodeAPER(value TargetRNCIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetRNCIDValueCodec) encodeBudgetValue(value TargetRNCID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCIDValueCodec) encodeChanged(value TargetRNCID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargeteNBIDValueCodec is the concrete ValueCodec[TargeteNBID].
type TargeteNBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TargeteNBID,

		error)
	encode func(TargeteNBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TargeteNBID, aper.DecodeState,

	) (TargeteNBID, aper.Snapshot,

	)
	compare func(TargeteNBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargeteNBIDValueCodec) New(value TargeteNBID,

) (TargeteNBIDAPERValue, error) {
	if c.encode == nil {
		return TargeteNBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargeteNBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargeteNBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargeteNBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargeteNBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargeteNBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargeteNBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargeteNBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargeteNBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargeteNBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargeteNBIDValueCodec) EncodeAPER(value TargeteNBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargeteNBIDValueCodec) encodeBudgetValue(value TargeteNBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargeteNBIDValueCodec) encodeChanged(value TargeteNBID,

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
func BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields ENBDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields MMEDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeRecommendedENBItemIEValueValidateS1APIEContainer(fields s32.RecommendedENBItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s32.BridgeRecommendedENBItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeRecommendedENBItemIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeRecommendedENBItemIEValueMethodRule(field.Value).Assignment
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
func BridgeTAIExtIEsValueValidateS1APExtensionContainer(fields s11.TAIExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAIExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAIExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTAIItemExtIEsValueValidateS1APExtensionContainer(fields s11.TAIItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TAIItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TAIItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTAIItemExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTAIItemIEValueValidateS1APIEContainer(fields TAIItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// TAIItemIEContainer is ProtocolIE-Container {{TAIItemIEs}} of TS 36.413: a list of TAIItemIEField values.
type TAIItemIEContainer []TAIItemIEField

func BridgeTargetNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields s11.TargetNgRanNodeIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TargetNgRanNodeIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TargetNgRanNodeIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargetNgRanNodeIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTargetRNCIDExtIEsValueValidateS1APExtensionContainer(fields s11.TargetRNCIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TargetRNCIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TargetRNCIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargetRNCIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ENBDirectInformationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueERABIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) ENBDirectInformationTransferIEValueERABIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBDirectInformationTransferIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransferIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBDirectInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ENBDirectInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
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

// MMEDirectInformationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEDirectInformationTransferIEs}} codec of TS 36.413.
func MMEDirectInformationTransferIEValueERABIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable) MMEDirectInformationTransferIEValueERABIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return MMEDirectInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEDirectInformationTransferIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEDirectInformationTransferIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransferIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEDirectInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v MMEDirectInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
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

// RecommendedENBItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{RecommendedENBItemIEs}} codec of TS 36.413.
func RecommendedENBItemIEValueERABIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable) s32.RecommendedENBItemIEValueERABIEContainerListValueCodec {
	codec := s33.RecommendedENBItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s32.RecommendedENBItemIEValueERABIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueERABIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.RecommendedENBItemIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.RecommendedENBItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueERABIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s33.BridgeRecommendedENBItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIItemIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{TAIItemIEs}} codec of TS 36.413.
func TAIItemIEValueERABIEContainerListCodec(table s00.TAIItemIEValueIETable) TAIItemIEValueERABIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TAIItemIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return TAIItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TAIItemIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TAIItemIEField
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
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TAIItemIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value TAIItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TAIItemIEContainer(value), fresh, budget)
	}, capture: func(v TAIItemIEValueERABIEContainerList, options aper.DecodeState) (TAIItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v TAIItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTAIItemIEValueCompareS1APERABIEContainerList(&v, &s)
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

// TAIItemExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TAIItemExtIEs}} codec of TS 36.413.
func TAIItemExtIEsValueExtensionFieldTableCodec(table s00.TAIItemExtIEsValueExtensionTable) s11.TAIItemExtIEsExtFieldValueCodec {
	if !*s00.BridgeTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIItemExtIEsExtFieldValueCodec{}
	}
	return func() s11.TAIItemExtIEsExtFieldValueCodec {
		sealed := s11.TAIItemExtIEsExtFieldValueCodec{}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIItemExtIEsExtField, error) {
			var field s11.TAIItemExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TAIItemExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TAIItemExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TAIItemExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TAIItemExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TAIItemExtIEsExtField, options aper.DecodeState) (s11.TAIItemExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetNgRanNodeIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TargetNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func TargetNgRanNodeIDExtIEsValueExtensionFieldTableCodec(table s00.TargetNgRanNodeIDExtIEsValueExtensionTable) s11.TargetNgRanNodeIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeTargetNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargetNgRanNodeIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.TargetNgRanNodeIDExtIEsExtFieldValueCodec {
		sealed := s11.TargetNgRanNodeIDExtIEsExtFieldValueCodec{}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargetNgRanNodeIDExtIEsExtField, error) {
			var field s11.TargetNgRanNodeIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TargetNgRanNodeIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetNgRanNodeIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TargetNgRanNodeIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TargetNgRanNodeIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TargetNgRanNodeIDExtIEsExtField, options aper.DecodeState) (s11.TargetNgRanNodeIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargetNgRanNodeIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetRNCIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TargetRNC-ID-ExtIEs}} codec of TS 36.413.
func TargetRNCIDExtIEsValueExtensionFieldTableCodec(table s00.TargetRNCIDExtIEsValueExtensionTable) s11.TargetRNCIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeTargetRNCIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargetRNCIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.TargetRNCIDExtIEsExtFieldValueCodec {
		sealed := s11.TargetRNCIDExtIEsExtFieldValueCodec{}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargetRNCIDExtIEsExtField, error) {
			var field s11.TargetRNCIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TargetRNCIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetRNCIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TargetRNCIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TargetRNCIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TargetRNCIDExtIEsExtField, options aper.DecodeState) (s11.TargetRNCIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargetRNCIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargeteNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TargeteNB-ID-ExtIEs}} codec of TS 36.413.
func TargeteNBIDExtIEsValueExtensionFieldTableCodec(table s00.TargeteNBIDExtIEsValueExtensionTable) s11.TargeteNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeTargeteNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargeteNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s11.TargeteNBIDExtIEsExtFieldValueCodec {
		sealed := s11.TargeteNBIDExtIEsExtFieldValueCodec{}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargeteNBIDExtIEsExtField, error) {
			var field s11.TargeteNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargeteNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TargeteNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TargeteNBIDExtIEsExtField, options aper.DecodeState) (s11.TargeteNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargeteNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIItemExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TAIItemExtIEs}} codec of TS 36.413.
func TAIItemExtIEsValueExtensionTableCodec(table s00.TAIItemExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TAIItemExtIEsExtContainerValueCodec {
	if !*s00.BridgeTAIItemExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TAIItemExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TAIItemExtIEsExtContainerValueCodec {
		sealed := s11.TAIItemExtIEsExtContainerValueCodec{}
		*s11.BridgeTAIItemExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TAIItemExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TAIItemExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TAIItemExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TAIItemExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TAIItemExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TAIItemExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeTAIItemExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TAIItemExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTAIItemExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTAIItemExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TAIItemExtIEsExtContainer, options aper.DecodeState) (s11.TAIItemExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTAIItemExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TAIItemExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTAIItemExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TargetNgRanNodeIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargetNgRanNode-ID-ExtIEs}} codec of TS 36.413.
func TargetNgRanNodeIDExtIEsValueExtensionTableCodec(table s00.TargetNgRanNodeIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TargetNgRanNodeIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargetNgRanNodeIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargetNgRanNodeIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TargetNgRanNodeIDExtIEsExtContainerValueCodec {
		sealed := s11.TargetNgRanNodeIDExtIEsExtContainerValueCodec{}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargetNgRanNodeIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TargetNgRanNodeIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TargetNgRanNodeIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TargetNgRanNodeIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetNgRanNodeIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TargetNgRanNodeIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TargetNgRanNodeIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TargetNgRanNodeIDExtIEsExtContainer, options aper.DecodeState) (s11.TargetNgRanNodeIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TargetNgRanNodeIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TargetRNCIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargetRNC-ID-ExtIEs}} codec of TS 36.413.
func TargetRNCIDExtIEsValueExtensionTableCodec(table s00.TargetRNCIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TargetRNCIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargetRNCIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargetRNCIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TargetRNCIDExtIEsExtContainerValueCodec {
		sealed := s11.TargetRNCIDExtIEsExtContainerValueCodec{}
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargetRNCIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TargetRNCIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TargetRNCIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TargetRNCIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargetRNCIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TargetRNCIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TargetRNCIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TargetRNCIDExtIEsExtContainer, options aper.DecodeState) (s11.TargetRNCIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TargetRNCIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TargeteNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargeteNB-ID-ExtIEs}} codec of TS 36.413.
func TargeteNBIDExtIEsValueExtensionTableCodec(table s00.TargeteNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TargeteNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargeteNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TargeteNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TargeteNBIDExtIEsExtContainerValueCodec {
		sealed := s11.TargeteNBIDExtIEsExtContainerValueCodec{}
		*s11.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TargeteNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TargeteNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TargeteNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargeteNBIDExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtContainer")
			}
			return fields, nil
		}
		*s11.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TargeteNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TargeteNBIDExtIEsExtContainer, options aper.DecodeState) (s11.TargeteNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TargeteNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBDirectInformationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueIEFieldTableCodec(table s00.ENBDirectInformationTransferIEValueIETable) ENBDirectInformationTransferIEFieldValueCodec {
	if !*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&table) {
		return ENBDirectInformationTransferIEFieldValueCodec{}
	}
	return ENBDirectInformationTransferIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEField, error) {
		var field ENBDirectInformationTransferIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransferIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEField")
		}
		return field, nil
	}, encode: func(field ENBDirectInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBDirectInformationTransferIEField, options aper.DecodeState) (ENBDirectInformationTransferIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBDirectInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
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

// MMEDirectInformationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEDirectInformationTransferIEs}} codec of TS 36.413.
func MMEDirectInformationTransferIEValueIEFieldTableCodec(table s00.MMEDirectInformationTransferIEValueIETable) MMEDirectInformationTransferIEFieldValueCodec {
	if !*s00.BridgeMMEDirectInformationTransferIEValueIETableFieldBound(&table) {
		return MMEDirectInformationTransferIEFieldValueCodec{}
	}
	return MMEDirectInformationTransferIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEField, error) {
		var field MMEDirectInformationTransferIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransferIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEField")
		}
		return field, nil
	}, encode: func(field MMEDirectInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v MMEDirectInformationTransferIEField, options aper.DecodeState) (MMEDirectInformationTransferIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEDirectInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
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

// TAIItemIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{TAIItemIEs}} codec of TS 36.413.
func TAIItemIEValueIEFieldTableCodec(table s00.TAIItemIEValueIETable) TAIItemIEFieldValueCodec {
	if !*s00.BridgeTAIItemIEValueIETableFieldBound(&table) {
		return TAIItemIEFieldValueCodec{}
	}
	return TAIItemIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEField, error) {
		var field TAIItemIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "TAIItemIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "TAIItemIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "TAIItemIEField")
		}
		return field, nil
	}, encode: func(field TAIItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v TAIItemIEField, options aper.DecodeState) (TAIItemIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTAIItemIEValueCompareS1APProtocolIEField(&v, &s)
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

// ENBDirectInformationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueIETableCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) ENBDirectInformationTransferIEContainerValueCodec {
	if !*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&table) {
		return ENBDirectInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBDirectInformationTransferIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransferIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ENBDirectInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBDirectInformationTransferIEContainer, options aper.DecodeState) (ENBDirectInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBDirectInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// MMEDirectInformationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEDirectInformationTransferIEs}} codec of TS 36.413.
func MMEDirectInformationTransferIEValueIETableCodec(table s00.MMEDirectInformationTransferIEValueIETable, bounds aper.ListBounds) MMEDirectInformationTransferIEContainerValueCodec {
	if !*s00.BridgeMMEDirectInformationTransferIEValueIETableFieldBound(&table) {
		return MMEDirectInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return MMEDirectInformationTransferIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEDirectInformationTransferIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransferIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEContainer")
		}
		return fields, nil
	},
		encode: func(fields MMEDirectInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v MMEDirectInformationTransferIEContainer, options aper.DecodeState) (MMEDirectInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v MMEDirectInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// TAIItemIEValueIETableCodec constructs the ProtocolIE-Container {{TAIItemIEs}} codec of TS 36.413.
func TAIItemIEValueIETableCodec(table s00.TAIItemIEValueIETable, bounds aper.ListBounds) TAIItemIEContainerValueCodec {
	if !*s00.BridgeTAIItemIEValueIETableFieldBound(&table) {
		return TAIItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return TAIItemIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TAIItemIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TAIItemIEField
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
			return nil, runtime.WrapDecodePath(err, "TAIItemIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "TAIItemIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TAIItemIEContainer")
		}
		return fields, nil
	},
		encode: func(fields TAIItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v TAIItemIEContainer, options aper.DecodeState) (TAIItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTAIItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v TAIItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBDirectInformationTransferIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransferIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(
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

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEDirectInformationTransferIEs}} codec of TS 36.413.
func MMEDirectInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable) MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEDirectInformationTransferIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransferIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(
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

// RecommendedENBItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{RecommendedENBItemIEs}} codec of TS 36.413.
func RecommendedENBItemIEValueProtocolErrorIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable) s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := s33.RecommendedENBItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.RecommendedENBItemIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.RecommendedENBItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s33.BridgeRecommendedENBItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIItemIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{TAIItemIEs}} codec of TS 36.413.
func TAIItemIEValueProtocolErrorIEContainerListCodec(table s00.TAIItemIEValueIETable) TAIItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TAIItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return TAIItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TAIItemIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TAIItemIEField
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
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TAIItemIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value TAIItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TAIItemIEContainer(value), fresh, budget)
	}, capture: func(v TAIItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTAIItemIEValueCompareS1APProtocolErrorIEContainerList(
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

// ENBDirectInformationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBDirectInformationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBDirectInformationTransferIEValueProtocolIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBDirectInformationTransferIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransferIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBDirectInformationTransferIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBDirectInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ENBDirectInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// MMEDirectInformationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEDirectInformationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEDirectInformationTransferIEValueProtocolIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable, bounds aper.ListBounds) MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEDirectInformationTransferIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEDirectInformationTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransferIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEDirectInformationTransferIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEDirectInformationTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEDirectInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MMEDirectInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// RecommendedENBItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {RecommendedENBItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func RecommendedENBItemIEValueProtocolIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable, bounds aper.ListBounds) s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec {
	codec := s33.RecommendedENBItemIEValueIETableCodec(table, bounds)
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.RecommendedENBItemIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.RecommendedENBItemIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "RecommendedENBItemIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "RecommendedENBItemIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s33.BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TAIItemIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {TAIItemIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func TAIItemIEValueProtocolIEContainerListCodec(table s00.TAIItemIEValueIETable, bounds aper.ListBounds) TAIItemIEValueProtocolIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return TAIItemIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return TAIItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TAIItemIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TAIItemIEField
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
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TAIItemIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TAIItemIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value TAIItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TAIItemIEContainer(value), fresh, budget)
	}, capture: func(v TAIItemIEValueProtocolIEContainerList, options aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v TAIItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeTAIItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// eNBDirectInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBDirectInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBDirectInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(v *ENBDirectInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(v *ENBDirectInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mMEDirectInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) MMEDirectInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (MMEDirectInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(v *MMEDirectInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(v *MMEDirectInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// recommendedENBItemIEValueProtocolOpenValue is the concrete protocolOpenValue[RecommendedENBItemIEValue].
type RecommendedENBItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.RecommendedENBItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.RecommendedENBItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// tAIExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAIExtIEsValue].
type TAIExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAIExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAIExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// tAIItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TAIItemExtIEsValue].
type TAIItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TAIItemExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TAIItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TAIItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTAIItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTAIItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionField(v *s11.TAIItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTAIItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTAIItemExtIEsExtFieldFieldReplay(v), *s11.BridgeTAIItemExtIEsExtFieldFieldWithoutReplay(v))
}

// tAIItemIEValueProtocolOpenValue is the concrete protocolOpenValue[TAIItemIEValue].
type TAIItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) TAIItemIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (TAIItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTAIItemIEValueCaptureS1APProtocolIEField(v *TAIItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeTAIItemIEValueCompareS1APProtocolIEField(v *TAIItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// targetNgRanNodeIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargetNgRanNodeIDExtIEsValue].
type TargetNgRanNodeIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TargetNgRanNodeIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TargetNgRanNodeIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TargetNgRanNodeIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTargetNgRanNodeIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTargetNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargetNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.TargetNgRanNodeIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTargetNgRanNodeIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTargetNgRanNodeIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargetNgRanNodeIDExtIEsExtFieldFieldWithoutReplay(v))
}

// targetRNCIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargetRNCIDExtIEsValue].
type TargetRNCIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TargetRNCIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TargetRNCIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TargetRNCIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTargetRNCIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTargetRNCIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargetRNCIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.TargetRNCIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTargetRNCIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTargetRNCIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargetRNCIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TargeteNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTargeteNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTargeteNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargeteNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s11.TargeteNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTargeteNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTargeteNBIDExtIEsExtFieldFieldReplay(v), *s11.BridgeTargeteNBIDExtIEsExtFieldFieldWithoutReplay(v))
}

// InterSystemInformationTransferTypeAPERValue is the concrete APERValue[InterSystemInformationTransferType].
type InterSystemInformationTransferTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterSystemInformationTransferType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterSystemInformationTransferTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterSystemInformationTransferTypeAPERValue) WithoutReplay() InterSystemInformationTransferTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetIDAPERValue is the concrete APERValue[TargetID].
type TargetIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   TargetID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetIDAPERValue) WithoutReplay() TargetIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIListAPERValue is the concrete APERValue[TAIList].
type TAIListAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIListAPERValue) WithoutReplay() TAIListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemAPERValue is the concrete APERValue[TAIItem].
type TAIItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   TAIItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemAPERValue) WithoutReplay() TAIItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InformationOnRecommendedCellsAndENBsForPagingAPERValue is the concrete APERValue[InformationOnRecommendedCellsAndENBsForPaging].
type InformationOnRecommendedCellsAndENBsForPagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   InformationOnRecommendedCellsAndENBsForPaging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InformationOnRecommendedCellsAndENBsForPagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InformationOnRecommendedCellsAndENBsForPagingAPERValue) WithoutReplay() InformationOnRecommendedCellsAndENBsForPagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferAPERValue is the concrete APERValue[ENBDirectInformationTransfer].
type ENBDirectInformationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBDirectInformationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferAPERValue) WithoutReplay() ENBDirectInformationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferAPERValue is the concrete APERValue[MMEDirectInformationTransfer].
type MMEDirectInformationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEDirectInformationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferAPERValue) WithoutReplay() MMEDirectInformationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RIMRoutingAddressAPERValue is the concrete APERValue[RIMRoutingAddress].
type RIMRoutingAddressAPERValue struct {
	context s00.BridgeCodecContext
	Value   RIMRoutingAddress

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RIMRoutingAddressAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMRoutingAddressAPERValue) WithoutReplay() RIMRoutingAddressAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RIMTransferAPERValue is the concrete APERValue[RIMTransfer].
type RIMTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   RIMTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RIMTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMTransferAPERValue) WithoutReplay() RIMTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RecommendedENBsForPagingAPERValue is the concrete APERValue[RecommendedENBsForPaging].
type RecommendedENBsForPagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   s33.RecommendedENBsForPaging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RecommendedENBsForPagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RecommendedENBsForPagingAPERValue) WithoutReplay() RecommendedENBsForPagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetNgRanNodeIDAPERValue is the concrete APERValue[TargetNgRanNodeID].
type TargetNgRanNodeIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   TargetNgRanNodeID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetNgRanNodeIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeIDAPERValue) WithoutReplay() TargetNgRanNodeIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetRNCIDAPERValue is the concrete APERValue[TargetRNCID].
type TargetRNCIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   TargetRNCID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetRNCIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCIDAPERValue) WithoutReplay() TargetRNCIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargeteNBIDAPERValue is the concrete APERValue[TargeteNBID].
type TargeteNBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   TargeteNBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargeteNBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargeteNBIDAPERValue) WithoutReplay() TargeteNBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTAIExtIEsValueValidateS1APIEContainer(fields s11.TAIExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAIExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAIExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTAIItemExtIEsValueValidateS1APIEContainer(fields s11.TAIItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTAIItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTAIItemExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTAIItemExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTargetNgRanNodeIDExtIEsValueValidateS1APIEContainer(fields s11.TargetNgRanNodeIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTargetNgRanNodeIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTargetNgRanNodeIDExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTargetNgRanNodeIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTargetRNCIDExtIEsValueValidateS1APIEContainer(fields s11.TargetRNCIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTargetRNCIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTargetRNCIDExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTargetRNCIDExtIEsValueMethodRule(field.Value).Assignment
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

// ENBDirectInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBDirectInformationTransferIEValueERABIEContainerList].
type ENBDirectInformationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, error)
	encode  func(ENBDirectInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransferIEValueERABIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) New(value ENBDirectInformationTransferIEValueERABIEContainerList) (ENBDirectInformationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBDirectInformationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBDirectInformationTransferIEs}} of TS 36.413: a list of information element fields.
type ENBDirectInformationTransferIEValueERABIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeENBDirectInformationTransferIEValueCaptureS1APERABIEContainerList(v *ENBDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APERABIEContainerList(v *ENBDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequiredIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverRequiredIEValueERABIEContainerList].
type HandoverRequiredIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, error)
	encode  func(HandoverRequiredIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequiredIEValueERABIEContainerList, aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, aper.Snapshot)
	compare func(HandoverRequiredIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredIEValueERABIEContainerListValueCodec) New(value HandoverRequiredIEValueERABIEContainerList) (HandoverRequiredIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredIEValueERABIEContainerListValueCodec) EncodeAPER(value HandoverRequiredIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredIEValueERABIEContainerListValueCodec) encodeBudgetValue(value HandoverRequiredIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredIEValueERABIEContainerListValueCodec) encodeChanged(value HandoverRequiredIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverRequiredIEs}} of TS 36.413: a list of information element fields.
type HandoverRequiredIEValueERABIEContainerList []HandoverRequiredIEValueProtocolIESingleContainer

// MMEDirectInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEDirectInformationTransferIEValueERABIEContainerList].
type MMEDirectInformationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, error)
	encode  func(MMEDirectInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransferIEValueERABIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) New(value MMEDirectInformationTransferIEValueERABIEContainerList) (MMEDirectInformationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEDirectInformationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEDirectInformationTransferIEs}} of TS 36.413: a list of information element fields.
type MMEDirectInformationTransferIEValueERABIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeMMEDirectInformationTransferIEValueCaptureS1APERABIEContainerList(v *MMEDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APERABIEContainerList(v *MMEDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBItemIEValueCompareS1APERABIEContainerList(v *s32.RecommendedENBItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			s33.BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[TAIItemIEValueERABIEContainerList].
type TAIItemIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemIEValueERABIEContainerList, error)
	encode  func(TAIItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemIEValueERABIEContainerList, aper.DecodeState) (TAIItemIEValueERABIEContainerList, aper.Snapshot)
	compare func(TAIItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemIEValueERABIEContainerListValueCodec) New(value TAIItemIEValueERABIEContainerList) (TAIItemIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TAIItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemIEValueERABIEContainerListValueCodec) EncodeAPER(value TAIItemIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemIEValueERABIEContainerListValueCodec) encodeBudgetValue(value TAIItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemIEValueERABIEContainerListValueCodec) encodeChanged(value TAIItemIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEValueERABIEContainerList is E-RAB-IE-ContainerList {{TAIItemIEs}} of TS 36.413: a list of information element fields.
type TAIItemIEValueERABIEContainerList []TAIItemIEValueProtocolIESingleContainer

func BridgeTAIItemIEValueCaptureS1APERABIEContainerList(v *TAIItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTAIItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIItemIEValueCompareS1APERABIEContainerList(v *TAIItemIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTAIItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBDirectInformationTransferIEFieldValueCodec is the concrete ValueCodec[ENBDirectInformationTransferIEField].
type ENBDirectInformationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEField, error)
	encode  func(ENBDirectInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransferIEField, aper.DecodeState) (ENBDirectInformationTransferIEField, aper.Snapshot)
	compare func(ENBDirectInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferIEFieldValueCodec) New(value ENBDirectInformationTransferIEField) (ENBDirectInformationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferIEFieldValueCodec) EncodeAPER(value ENBDirectInformationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferIEFieldValueCodec) encodeBudgetValue(value ENBDirectInformationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferIEFieldValueCodec) encodeChanged(value ENBDirectInformationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredIEFieldValueCodec is the concrete ValueCodec[HandoverRequiredIEField].
type HandoverRequiredIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequiredIEField, error)
	encode  func(HandoverRequiredIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequiredIEField, aper.DecodeState) (HandoverRequiredIEField, aper.Snapshot)
	compare func(HandoverRequiredIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredIEFieldValueCodec) New(value HandoverRequiredIEField) (HandoverRequiredIEFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredIEFieldValueCodec) EncodeAPER(value HandoverRequiredIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredIEFieldValueCodec) encodeBudgetValue(value HandoverRequiredIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredIEFieldValueCodec) encodeChanged(value HandoverRequiredIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferIEFieldValueCodec is the concrete ValueCodec[MMEDirectInformationTransferIEField].
type MMEDirectInformationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEField, error)
	encode  func(MMEDirectInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransferIEField, aper.DecodeState) (MMEDirectInformationTransferIEField, aper.Snapshot)
	compare func(MMEDirectInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferIEFieldValueCodec) New(value MMEDirectInformationTransferIEField) (MMEDirectInformationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferIEFieldValueCodec) EncodeAPER(value MMEDirectInformationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferIEFieldValueCodec) encodeBudgetValue(value MMEDirectInformationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferIEFieldValueCodec) encodeChanged(value MMEDirectInformationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEFieldValueCodec is the concrete ValueCodec[TAIItemIEField].
type TAIItemIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemIEField, error)
	encode  func(TAIItemIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemIEField, aper.DecodeState) (TAIItemIEField, aper.Snapshot)
	compare func(TAIItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemIEFieldValueCodec) New(value TAIItemIEField) (TAIItemIEFieldAPERValue, error) {
	if c.encode == nil {
		return TAIItemIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemIEFieldValueCodec) EncodeAPER(value TAIItemIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemIEFieldValueCodec) encodeBudgetValue(value TAIItemIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemIEFieldValueCodec) encodeChanged(value TAIItemIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEContainerValueCodec is the concrete ValueCodec[ENBDirectInformationTransferIEContainer].
type ENBDirectInformationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEContainer, error)
	encode  func(ENBDirectInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransferIEContainer, aper.DecodeState) (ENBDirectInformationTransferIEContainer, aper.Snapshot)
	compare func(ENBDirectInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferIEContainerValueCodec) New(value ENBDirectInformationTransferIEContainer) (ENBDirectInformationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferIEContainerValueCodec) EncodeAPER(value ENBDirectInformationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferIEContainerValueCodec) encodeBudgetValue(value ENBDirectInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferIEContainerValueCodec) encodeChanged(value ENBDirectInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredIEContainerValueCodec is the concrete ValueCodec[HandoverRequiredIEContainer].
type HandoverRequiredIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequiredIEContainer, error)
	encode  func(HandoverRequiredIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequiredIEContainer, aper.DecodeState) (HandoverRequiredIEContainer, aper.Snapshot)
	compare func(HandoverRequiredIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredIEContainerValueCodec) New(value HandoverRequiredIEContainer) (HandoverRequiredIEContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredIEContainerValueCodec) EncodeAPER(value HandoverRequiredIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredIEContainerValueCodec) encodeBudgetValue(value HandoverRequiredIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredIEContainerValueCodec) encodeChanged(value HandoverRequiredIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferIEContainerValueCodec is the concrete ValueCodec[MMEDirectInformationTransferIEContainer].
type MMEDirectInformationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEContainer, error)
	encode  func(MMEDirectInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransferIEContainer, aper.DecodeState) (MMEDirectInformationTransferIEContainer, aper.Snapshot)
	compare func(MMEDirectInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferIEContainerValueCodec) New(value MMEDirectInformationTransferIEContainer) (MMEDirectInformationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferIEContainerValueCodec) EncodeAPER(value MMEDirectInformationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferIEContainerValueCodec) encodeBudgetValue(value MMEDirectInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferIEContainerValueCodec) encodeChanged(value MMEDirectInformationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEContainerValueCodec is the concrete ValueCodec[TAIItemIEContainer].
type TAIItemIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemIEContainer, error)
	encode  func(TAIItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemIEContainer, aper.DecodeState) (TAIItemIEContainer, aper.Snapshot)
	compare func(TAIItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemIEContainerValueCodec) New(value TAIItemIEContainer) (TAIItemIEContainerAPERValue, error) {
	if c.encode == nil {
		return TAIItemIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemIEContainerValueCodec) EncodeAPER(value TAIItemIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemIEContainerValueCodec) encodeBudgetValue(value TAIItemIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemIEContainerValueCodec) encodeChanged(value TAIItemIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeTAIItemIEValueCaptureS1APProtocolIEContainer(v *TAIItemIEContainer, s *aper.SemanticCapture) {
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
			BridgeTAIItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIItemIEValueCompareS1APProtocolIEContainer(v *TAIItemIEContainer, s *aper.SemanticComparison) {
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
			BridgeTAIItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBDirectInformationTransferIEValueProtocolErrorIEContainerList].
type ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBDirectInformationTransferIEValueProtocolErrorIEContainerList) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBDirectInformationTransferIEs}} of TS 36.413: a list of information element fields.
type ENBDirectInformationTransferIEValueProtocolErrorIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverRequiredIEValueProtocolErrorIEContainerList].
type HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, error)
	encode  func(HandoverRequiredIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequiredIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) New(value HandoverRequiredIEValueProtocolErrorIEContainerList) (HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value HandoverRequiredIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value HandoverRequiredIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverRequiredIEs}} of TS 36.413: a list of information element fields.
type HandoverRequiredIEValueProtocolErrorIEContainerList []HandoverRequiredIEValueProtocolIESingleContainer

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEDirectInformationTransferIEValueProtocolErrorIEContainerList].
type MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEDirectInformationTransferIEValueProtocolErrorIEContainerList) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEDirectInformationTransferIEs}} of TS 36.413: a list of information element fields.
type MMEDirectInformationTransferIEValueProtocolErrorIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBItemIEValueCompareS1APProtocolErrorIEContainerList(v *s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			s33.BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[TAIItemIEValueProtocolErrorIEContainerList].
type TAIItemIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, error)
	encode  func(TAIItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(TAIItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemIEValueProtocolErrorIEContainerListValueCodec) New(value TAIItemIEValueProtocolErrorIEContainerList) (TAIItemIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value TAIItemIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value TAIItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value TAIItemIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{TAIItemIEs}} of TS 36.413: a list of information element fields.
type TAIItemIEValueProtocolErrorIEContainerList []TAIItemIEValueProtocolIESingleContainer

func BridgeTAIItemIEValueCaptureS1APProtocolErrorIEContainerList(v *TAIItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTAIItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIItemIEValueCompareS1APProtocolErrorIEContainerList(v *TAIItemIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTAIItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBDirectInformationTransferIEValueProtocolIEContainerList].
type ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBDirectInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) New(value ENBDirectInformationTransferIEValueProtocolIEContainerList) (ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBDirectInformationTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBDirectInformationTransferIEValueProtocolIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *ENBDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(v *ENBDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequiredIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverRequiredIEValueProtocolIEContainerList].
type HandoverRequiredIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, error)
	encode  func(HandoverRequiredIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequiredIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredIEValueProtocolIEContainerListValueCodec) New(value HandoverRequiredIEValueProtocolIEContainerList) (HandoverRequiredIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredIEValueProtocolIEContainerListValueCodec) EncodeAPER(value HandoverRequiredIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value HandoverRequiredIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredIEValueProtocolIEContainerListValueCodec) encodeChanged(value HandoverRequiredIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverRequiredIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverRequiredIEValueProtocolIEContainerList []HandoverRequiredIEValueProtocolIESingleContainer

// MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEDirectInformationTransferIEValueProtocolIEContainerList].
type MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, error)
	encode  func(MMEDirectInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) New(value MMEDirectInformationTransferIEValueProtocolIEContainerList) (MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEDirectInformationTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEDirectInformationTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEDirectInformationTransferIEValueProtocolIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *MMEDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(v *MMEDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainerList(v *s32.RecommendedENBItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			s33.BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[TAIItemIEValueProtocolIEContainerList].
type TAIItemIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, error)
	encode  func(TAIItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TAIItemIEValueProtocolIEContainerList, aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(TAIItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAIItemIEValueProtocolIEContainerListValueCodec) New(value TAIItemIEValueProtocolIEContainerList) (TAIItemIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TAIItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAIItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAIItemIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAIItemIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAIItemIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAIItemIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAIItemIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAIItemIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAIItemIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAIItemIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAIItemIEValueProtocolIEContainerListValueCodec) EncodeAPER(value TAIItemIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAIItemIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value TAIItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAIItemIEValueProtocolIEContainerListValueCodec) encodeChanged(value TAIItemIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAIItemIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {TAIItemIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type TAIItemIEValueProtocolIEContainerList []TAIItemIEValueProtocolIESingleContainer

func BridgeTAIItemIEValueCaptureS1APProtocolIEContainerList(v *TAIItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTAIItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTAIItemIEValueCompareS1APProtocolIEContainerList(v *TAIItemIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTAIItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBDirectInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBDirectInformationTransferIEValueERABIEContainerList].
type ENBDirectInformationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBDirectInformationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBDirectInformationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBDirectInformationTransferIEs}} of TS 36.413: a single information element field.
type ENBDirectInformationTransferIEValueProtocolIESingleContainer = ENBDirectInformationTransferIEField

func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *ENBDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *ENBDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequiredIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverRequiredIEValueERABIEContainerList].
type HandoverRequiredIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequiredIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEValueERABIEContainerListAPERValue) WithoutReplay() HandoverRequiredIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequiredIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverRequiredIEs}} of TS 36.413: a single information element field.
type HandoverRequiredIEValueProtocolIESingleContainer = HandoverRequiredIEField

// MMEDirectInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEDirectInformationTransferIEValueERABIEContainerList].
type MMEDirectInformationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEDirectInformationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEDirectInformationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEDirectInformationTransferIEs}} of TS 36.413: a single information element field.
type MMEDirectInformationTransferIEValueProtocolIESingleContainer = MMEDirectInformationTransferIEField

func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *MMEDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *MMEDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueERABIEContainerListAPERValue is the concrete APERValue[TAIItemIEValueERABIEContainerList].
type TAIItemIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEValueERABIEContainerListAPERValue) WithoutReplay() TAIItemIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEFieldAPERValue is the concrete APERValue[ENBDirectInformationTransferIEField].
type ENBDirectInformationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBDirectInformationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEFieldAPERValue) WithoutReplay() ENBDirectInformationTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequiredIEFieldAPERValue is the concrete APERValue[HandoverRequiredIEField].
type HandoverRequiredIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequiredIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEFieldAPERValue) WithoutReplay() HandoverRequiredIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferIEFieldAPERValue is the concrete APERValue[MMEDirectInformationTransferIEField].
type MMEDirectInformationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEDirectInformationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEFieldAPERValue) WithoutReplay() MMEDirectInformationTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemIEFieldAPERValue is the concrete APERValue[TAIItemIEField].
type TAIItemIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEFieldAPERValue) WithoutReplay() TAIItemIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEContainerAPERValue is the concrete APERValue[ENBDirectInformationTransferIEContainer].
type ENBDirectInformationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBDirectInformationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEContainerAPERValue) WithoutReplay() ENBDirectInformationTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequiredIEContainerAPERValue is the concrete APERValue[HandoverRequiredIEContainer].
type HandoverRequiredIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequiredIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEContainerAPERValue) WithoutReplay() HandoverRequiredIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferIEContainerAPERValue is the concrete APERValue[MMEDirectInformationTransferIEContainer].
type MMEDirectInformationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEDirectInformationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEContainerAPERValue) WithoutReplay() MMEDirectInformationTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemIEContainerAPERValue is the concrete APERValue[TAIItemIEContainer].
type TAIItemIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEContainerAPERValue) WithoutReplay() TAIItemIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBDirectInformationTransferIEValueProtocolErrorIEContainerList].
type ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBDirectInformationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverRequiredIEValueProtocolErrorIEContainerList].
type HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequiredIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEDirectInformationTransferIEValueProtocolErrorIEContainerList].
type MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEDirectInformationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[TAIItemIEValueProtocolErrorIEContainerList].
type TAIItemIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() TAIItemIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBDirectInformationTransferIEValueProtocolIEContainerList].
type ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBDirectInformationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequiredIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverRequiredIEValueProtocolIEContainerList].
type HandoverRequiredIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRequiredIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredIEValueProtocolIEContainerListAPERValue) WithoutReplay() HandoverRequiredIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEDirectInformationTransferIEValueProtocolIEContainerList].
type MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEDirectInformationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAIItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[TAIItemIEValueProtocolIEContainerList].
type TAIItemIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TAIItemIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAIItemIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAIItemIEValueProtocolIEContainerListAPERValue) WithoutReplay() TAIItemIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APENBDirectInformationTransfer(v *ENBDirectInformationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBDirectInformationTransfer(v *ENBDirectInformationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBDirectInformationTransferIEValue(v *ENBDirectInformationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(121):
			{
				f := s.Begin()
				s.Bool(v.rowInterSystemInformationTransferTypeEDT == nil)
				if v.rowInterSystemInformationTransferTypeEDT != nil {
					BridgeCaptureS1APInterSystemInformationTransferType(v.rowInterSystemInformationTransferTypeEDT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBDirectInformationTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBDirectInformationTransferIEValue {
	BridgeCaptureS1APENBDirectInformationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBDirectInformationTransferIEValue(v *ENBDirectInformationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(121):
			{
				f := s.Begin()
				s.Bool(v.rowInterSystemInformationTransferTypeEDT == nil)
				if v.rowInterSystemInformationTransferTypeEDT != nil {
					BridgeCompareS1APInterSystemInformationTransferType(v.rowInterSystemInformationTransferTypeEDT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBDirectInformationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBDirectInformationTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APHandoverRequiredIEValue(v *HandoverRequiredIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s00.BridgeCaptureS1APHandoverType(v.rowHandoverType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowTargetID == nil)
				if v.rowTargetID != nil {
					BridgeCaptureS1APTargetID(v.rowTargetID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(79):
			{
				f := s.Begin()
				s.Bool(v.rowDirectForwardingPathAvailability == nil)
				if v.rowDirectForwardingPathAvailability != nil {
					s00.BridgeCaptureS1APDirectForwardingPathAvailability(v.rowDirectForwardingPathAvailability, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(125):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCHOIndication == nil)
				if v.rowSRVCCHOIndication != nil {
					s00.BridgeCaptureS1APSRVCCHOIndication(v.rowSRVCCHOIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(104):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainer == nil)
				if v.rowSourceToTargetTransparentContainer != nil {
					s00.BridgeCaptureS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(138):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainerSecondary == nil)
				if v.rowSourceToTargetTransparentContainerSecondary != nil {
					s00.BridgeCaptureS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainerSecondary, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(132):
			{
				f := s.Begin()
				s.Bool(v.rowMSClassmark2 == nil)
				if v.rowMSClassmark2 != nil {
					s00.BridgeCaptureS1APMSClassmark2(v.rowMSClassmark2, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(133):
			{
				f := s.Begin()
				s.Bool(v.rowMSClassmark3 == nil)
				if v.rowMSClassmark3 != nil {
					s00.BridgeCaptureS1APMSClassmark3(v.rowMSClassmark3, s)
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
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s00.BridgeCaptureS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(150):
			{
				f := s.Begin()
				s.Bool(v.rowPSServiceNotAvailable == nil)
				if v.rowPSServiceNotAvailable != nil {
					s00.BridgeCaptureS1APPSServiceNotAvailable(v.rowPSServiceNotAvailable, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequiredIEValue) captureSemantics(s aper.SemanticCapture) HandoverRequiredIEValue {
	BridgeCaptureS1APHandoverRequiredIEValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverRequiredIEValue(v *HandoverRequiredIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverType == nil)
				if v.rowHandoverType != nil {
					s02.BridgeCompareS1APHandoverType(v.rowHandoverType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowTargetID == nil)
				if v.rowTargetID != nil {
					BridgeCompareS1APTargetID(v.rowTargetID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(79):
			{
				f := s.Begin()
				s.Bool(v.rowDirectForwardingPathAvailability == nil)
				if v.rowDirectForwardingPathAvailability != nil {
					s02.BridgeCompareS1APDirectForwardingPathAvailability(v.rowDirectForwardingPathAvailability, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(125):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCHOIndication == nil)
				if v.rowSRVCCHOIndication != nil {
					s06.BridgeCompareS1APSRVCCHOIndication(v.rowSRVCCHOIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(104):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainer == nil)
				if v.rowSourceToTargetTransparentContainer != nil {
					s07.BridgeCompareS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(138):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainerSecondary == nil)
				if v.rowSourceToTargetTransparentContainerSecondary != nil {
					s07.BridgeCompareS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainerSecondary, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(132):
			{
				f := s.Begin()
				s.Bool(v.rowMSClassmark2 == nil)
				if v.rowMSClassmark2 != nil {
					s02.BridgeCompareS1APMSClassmark2(v.rowMSClassmark2, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(133):
			{
				f := s.Begin()
				s.Bool(v.rowMSClassmark3 == nil)
				if v.rowMSClassmark3 != nil {
					s02.BridgeCompareS1APMSClassmark3(v.rowMSClassmark3, s)
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
		case s00.ProtocolIEID(145):
			{
				f := s.Begin()
				s.Bool(v.rowCellAccessMode == nil)
				if v.rowCellAccessMode != nil {
					s02.BridgeCompareS1APCellAccessMode(v.rowCellAccessMode, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(150):
			{
				f := s.Begin()
				s.Bool(v.rowPSServiceNotAvailable == nil)
				if v.rowPSServiceNotAvailable != nil {
					s02.BridgeCompareS1APPSServiceNotAvailable(v.rowPSServiceNotAvailable, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRequiredIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverRequiredIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(v *InformationOnRecommendedCellsAndENBsForPaging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCaptureS1APRecommendedCellsForPaging(&v.RecommendedCellsForPaging, s)
	s33.BridgeCaptureS1APRecommendedENBsForPaging(&v.RecommendENBsForPaging, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(v *InformationOnRecommendedCellsAndENBsForPaging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APRecommendedCellsForPaging(&v.RecommendedCellsForPaging, s)
	s33.BridgeCompareS1APRecommendedENBsForPaging(&v.RecommendENBsForPaging, s)
	s.Bool(v.IEExtensions == nil)
	s13.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInterSystemInformationTransferType(v *InterSystemInformationTransferType, s *aper.SemanticCapture) {
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
	case s00.InterSystemInformationTransferTypeChoiceRIMTransfer:
		{
			f := s.Begin()
			s.Bool(v.RIMTransfer == nil)
			if v.RIMTransfer != nil {
				BridgeCaptureS1APRIMTransfer(v.RIMTransfer, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInterSystemInformationTransferType(v *InterSystemInformationTransferType, s *aper.SemanticComparison) {
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
	case s00.InterSystemInformationTransferTypeChoiceRIMTransfer:
		{
			f := s.Begin()
			s.Bool(v.RIMTransfer == nil)
			if v.RIMTransfer != nil {
				BridgeCompareS1APRIMTransfer(v.RIMTransfer, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEDirectInformationTransfer(v *MMEDirectInformationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEDirectInformationTransfer(v *MMEDirectInformationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEDirectInformationTransferIEValue(v *MMEDirectInformationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(122):
			{
				f := s.Begin()
				s.Bool(v.rowInterSystemInformationTransferTypeMDT == nil)
				if v.rowInterSystemInformationTransferTypeMDT != nil {
					BridgeCaptureS1APInterSystemInformationTransferType(v.rowInterSystemInformationTransferTypeMDT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEDirectInformationTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEDirectInformationTransferIEValue {
	BridgeCaptureS1APMMEDirectInformationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEDirectInformationTransferIEValue(v *MMEDirectInformationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(122):
			{
				f := s.Begin()
				s.Bool(v.rowInterSystemInformationTransferTypeMDT == nil)
				if v.rowInterSystemInformationTransferTypeMDT != nil {
					BridgeCompareS1APInterSystemInformationTransferType(v.rowInterSystemInformationTransferTypeMDT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEDirectInformationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEDirectInformationTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APRIMRoutingAddress(v *RIMRoutingAddress, s *aper.SemanticCapture) {
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
	case s00.RIMRoutingAddressChoiceGERANCellID:
		{
			f := s.Begin()
			s.Bool(v.GERANCellID == nil)
			if v.GERANCellID != nil {
				s18.BridgeCaptureS1APGERANCellID(v.GERANCellID, s)
			}
			s.End(f, nil, false)
		}
	case s00.RIMRoutingAddressChoiceTargetRNCID:
		{
			f := s.Begin()
			s.Bool(v.TargetRNCID == nil)
			if v.TargetRNCID != nil {
				BridgeCaptureS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, nil, false)
		}
	case s00.RIMRoutingAddressChoiceEHRPDSectorID:
		s.Bytes(v.EHRPDSectorID)
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APRIMRoutingAddress(v *RIMRoutingAddress, s *aper.SemanticComparison) {
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
	case s00.RIMRoutingAddressChoiceGERANCellID:
		{
			f := s.Begin()
			s.Bool(v.GERANCellID == nil)
			if v.GERANCellID != nil {
				s18.BridgeCompareS1APGERANCellID(v.GERANCellID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.RIMRoutingAddressChoiceTargetRNCID:
		{
			f := s.Begin()
			s.Bool(v.TargetRNCID == nil)
			if v.TargetRNCID != nil {
				BridgeCompareS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.RIMRoutingAddressChoiceEHRPDSectorID:
		s.Bytes(v.EHRPDSectorID)
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 1 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APRIMTransfer(v *RIMTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APRIMInformation(&v.RIMInformation, s)
	{
		f := s.Begin()
		s.Bool(v.RIMRoutingAddress == nil)
		if v.RIMRoutingAddress != nil {
			BridgeCaptureS1APRIMRoutingAddress(v.RIMRoutingAddress, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRIMTransfer(v *RIMTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s06.BridgeCompareS1APRIMInformation(&v.RIMInformation, s)
	{
		f := s.Begin()
		s.Bool(v.RIMRoutingAddress == nil)
		if v.RIMRoutingAddress != nil {
			BridgeCompareS1APRIMRoutingAddress(v.RIMRoutingAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s14.BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIItem(v *TAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAI(&v.TAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTAIItemExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIItem(v *TAIItem, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAI(&v.TAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIItemIEValue(v *TAIItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(47):
			{
				f := s.Begin()
				s.Bool(v.rowTAIItem == nil)
				if v.rowTAIItem != nil {
					BridgeCaptureS1APTAIItem(v.rowTAIItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TAIItemIEValue) captureSemantics(s aper.SemanticCapture) TAIItemIEValue {
	BridgeCaptureS1APTAIItemIEValue(&v, &s)
	return v
}
func BridgeCompareS1APTAIItemIEValue(v *TAIItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(47):
			{
				f := s.Begin()
				s.Bool(v.rowTAIItem == nil)
				if v.rowTAIItem != nil {
					BridgeCompareS1APTAIItem(v.rowTAIItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TAIItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APTAIItemIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTAIList(v *TAIList, s *aper.SemanticCapture) {
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
			BridgeTAIItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APTAIList(v *TAIList, s *aper.SemanticComparison) {
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
			BridgeTAIItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APTargetID(v *TargetID, s *aper.SemanticCapture) {
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
	case s00.TargetIDChoiceTargeteNBID:
		{
			f := s.Begin()
			s.Bool(v.TargeteNBID == nil)
			if v.TargeteNBID != nil {
				BridgeCaptureS1APTargeteNBID(v.TargeteNBID, s)
			}
			s.End(f, nil, false)
		}
	case s00.TargetIDChoiceTargetRNCID:
		{
			f := s.Begin()
			s.Bool(v.TargetRNCID == nil)
			if v.TargetRNCID != nil {
				BridgeCaptureS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, nil, false)
		}
	case s00.TargetIDChoiceCGI:
		{
			f := s.Begin()
			s.Bool(v.CGI == nil)
			if v.CGI != nil {
				s14.BridgeCaptureS1APCGI(v.CGI, s)
			}
			s.End(f, nil, false)
		}
	case s00.TargetIDChoiceTargetgNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.TargetgNgRanNodeID == nil)
			if v.TargetgNgRanNodeID != nil {
				BridgeCaptureS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APTargetID(v *TargetID, s *aper.SemanticComparison) {
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
	case s00.TargetIDChoiceTargeteNBID:
		{
			f := s.Begin()
			s.Bool(v.TargeteNBID == nil)
			if v.TargeteNBID != nil {
				BridgeCompareS1APTargeteNBID(v.TargeteNBID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.TargetIDChoiceTargetRNCID:
		{
			f := s.Begin()
			s.Bool(v.TargetRNCID == nil)
			if v.TargetRNCID != nil {
				BridgeCompareS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.TargetIDChoiceCGI:
		{
			f := s.Begin()
			s.Bool(v.CGI == nil)
			if v.CGI != nil {
				s14.BridgeCompareS1APCGI(v.CGI, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.TargetIDChoiceTargetgNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.TargetgNgRanNodeID == nil)
			if v.TargetgNgRanNodeID != nil {
				BridgeCompareS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APTargetNgRanNodeID(v *TargetNgRanNodeID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCaptureS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s18.BridgeCaptureS1APFiveGSTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargetNgRanNodeIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTargetNgRanNodeID(v *TargetNgRanNodeID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s19.BridgeCompareS1APGlobalRANNODEID(&v.GlobalRANNODEID, s)
	s18.BridgeCompareS1APFiveGSTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTargetRNCID(v *TargetRNCID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APLAI(&v.LAI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s00.BridgeCaptureS1APRAC(v.RAC, s)
		}
		s.End(f, nil, false)
	}
	s00.BridgeCaptureS1APRNCID(&v.RNCID, s)
	{
		f := s.Begin()
		s.Bool(v.ExtendedRNCID == nil)
		if v.ExtendedRNCID != nil {
			s00.BridgeCaptureS1APExtendedRNCID(v.ExtendedRNCID, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTargetRNCID(v *TargetRNCID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APLAI(&v.LAI, s)
	{
		f := s.Begin()
		s.Bool(v.RAC == nil)
		if v.RAC != nil {
			s06.BridgeCompareS1APRAC(v.RAC, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s06.BridgeCompareS1APRNCID(&v.RNCID, s)
	{
		f := s.Begin()
		s.Bool(v.ExtendedRNCID == nil)
		if v.ExtendedRNCID != nil {
			s02.BridgeCompareS1APExtendedRNCID(v.ExtendedRNCID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTargeteNBID(v *TargeteNBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCaptureS1APGlobalENBID(&v.GlobalENBID, s)
	s32.BridgeCaptureS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTargeteNBID(v *TargeteNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s18.BridgeCompareS1APGlobalENBID(&v.GlobalENBID, s)
	s32.BridgeCompareS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// InformationOnRecommendedCellsAndENBsForPaging represents the ASN.1 type InformationOnRecommendedCellsAndENBsForPaging (SEQUENCE).
type InformationOnRecommendedCellsAndENBsForPaging struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	received                  bool
	withoutReplay             bool
	receivedAbsolute          bool
	receivedBytes             aper.WireSpan
	receivedLocation          aper.Location
	RecommendedCellsForPaging s26.RecommendedCellsForPaging                                       `asn1:"tag:0,context,implicit"`
	RecommendENBsForPaging    s33.RecommendedENBsForPaging                                        `asn1:"tag:1,context,implicit"`
	IEExtensions              s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef         bool                                                                `asn1:"-" json:"-"`
	extCount                  int64                                                               `asn1:"-" json:"-"`
	extPresent                []bool                                                              `asn1:"-" json:"-"`
	extData                   [][]byte                                                            `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding                                                   `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding                                              `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}

// RIMTransfer represents the ASN.1 type RIMTransfer (SEQUENCE).
type RIMTransfer struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	RIMInformation    s00.RIMInformation                `asn1:"tag:0,context,implicit"`
	RIMRoutingAddress *RIMRoutingAddress                `asn1:"tag:1,context,explicit,optional" json:"RIMRoutingAddress,omitempty"`
	IEExtensions      s10.RIMTransferExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// RIMRoutingAddress represents the ASN.1 CHOICE type RIMRoutingAddress.
type RIMRoutingAddress struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	GERANCellID        *s18.GERANCellID      `json:"GERANCellID,omitempty"`
	TargetRNCID        *TargetRNCID          `json:"TargetRNCID,omitempty"`
	EHRPDSectorID      []byte                `json:"EHRPDSectorID,omitzero"`
}

// NewRIMRoutingAddressGERANCellID creates a RIMRoutingAddress with the gERAN-Cell-ID alternative.
func BridgeNewRIMRoutingAddressGERANCellIDLegacy(v s18.GERANCellID) RIMRoutingAddress {
	return RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceGERANCellID,
		GERANCellID: &v,
	}
}

// NewRIMRoutingAddressTargetRNCID creates a RIMRoutingAddress with the targetRNC-ID alternative.
func BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v TargetRNCID) RIMRoutingAddress {
	return RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewRIMRoutingAddressEHRPDSectorID creates a RIMRoutingAddress with the eHRPD-Sector-ID alternative.
func BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v []byte) RIMRoutingAddress {
	return RIMRoutingAddress{
		Choice:        s00.RIMRoutingAddressChoiceEHRPDSectorID,
		EHRPDSectorID: v,
	}
}

// TargetID represents the ASN.1 CHOICE type TargetID.
type TargetID struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	TargeteNBID        *TargeteNBID          `json:"TargeteNBID,omitempty"`
	TargetRNCID        *TargetRNCID          `json:"TargetRNCID,omitempty"`
	CGI                *s14.CGI              `json:"CGI,omitempty"`
	TargetgNgRanNodeID *TargetNgRanNodeID    `json:"TargetgNgRanNodeID,omitempty"`
}

// TargeteNBID represents the ASN.1 type TargeteNB-ID (SEQUENCE).
type TargeteNBID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalENBID       s18.GlobalENBID                   `asn1:"tag:0,context,implicit"`
	SelectedTAI       s32.TAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.TargeteNBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TargetRNCID represents the ASN.1 type TargetRNC-ID (SEQUENCE).
type TargetRNCID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	LAI               s18.LAI                           `asn1:"tag:0,context,implicit"`
	RAC               *s00.RAC                          `asn1:"tag:1,context,implicit,optional" json:"RAC,omitempty"`
	RNCID             s00.RNCID                         `asn1:"tag:2,context,implicit"`
	ExtendedRNCID     *s00.ExtendedRNCID                `asn1:"tag:3,context,implicit,optional" json:"ExtendedRNCID,omitempty"`
	IEExtensions      s11.TargetRNCIDExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TargetNgRanNodeID represents the ASN.1 type TargetNgRanNode-ID (SEQUENCE).
type TargetNgRanNodeID struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	GlobalRANNODEID   s19.GlobalRANNODEID                     `asn1:"tag:0,context,explicit"`
	SelectedTAI       s18.FiveGSTAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s11.TargetNgRanNodeIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                    `asn1:"-" json:"-"`
	extCount          int64                                   `asn1:"-" json:"-"`
	extPresent        []bool                                  `asn1:"-" json:"-"`
	extData           [][]byte                                `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes InformationOnRecommendedCellsAndENBsForPaging to APER format.
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s26.BridgeRecommendedCellsForPagingMethodMarshalAPERTo(&v.RecommendedCellsForPaging, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding recommendedCellsForPaging: %w", err)
	}
	if err := s33.BridgeRecommendedENBsForPagingMethodMarshalAPERTo(&v.RecommendENBsForPaging, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding recommendENBsForPaging: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes InformationOnRecommendedCellsAndENBsForPaging from APER format.
func (v *InformationOnRecommendedCellsAndENBsForPaging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InformationOnRecommendedCellsAndENBsForPaging with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InformationOnRecommendedCellsAndENBsForPaging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	bb.EnterComponent("InformationOnRecommendedCellsAndENBsForPaging")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	padding, err := aper.CaptureFinalBits(bb, "InformationOnRecommendedCellsAndENBsForPaging")
	if err != nil {
		return runtime.WrapDecodePath(err, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InformationOnRecommendedCellsAndENBsForPaging{}
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
	toleranceMark_recommendedcellsforpaging := bb.EnterComponent("RecommendedCellsForPaging")
	if err := s26.BridgeRecommendedCellsForPagingMethodUnmarshalAPERFrom(&v.RecommendedCellsForPaging, bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellsForPaging")
	}
	bb.LeaveComponent(toleranceMark_recommendedcellsforpaging)
	toleranceMark_recommendenbsforpaging := bb.EnterComponent("RecommendENBsForPaging")
	if err := s33.BridgeRecommendedENBsForPagingMethodUnmarshalAPERFrom(&v.RecommendENBsForPaging, bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendENBsForPaging")
	}
	bb.LeaveComponent(toleranceMark_recommendenbsforpaging)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RIMTransfer to APER format.
func (v *RIMTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RIMTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.RIMRoutingAddress != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.RIMInformation), 0, 0, false); err != nil {
		return fmt.Errorf("encoding rIMInformation: %w", err)
	}
	if v.RIMRoutingAddress != nil {
		if err := v.RIMRoutingAddress.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding rIMRoutingAddress: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s10.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RIMTransfer from APER format.
func (v *RIMTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RIMTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RIMTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RIMTransfer")
	}
	bb.EnterComponent("RIMTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RIMTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "RIMTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "RIMTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RIMTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RIMTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rimroutingaddress, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_riminformation, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RIMInformation")
	}
	v.RIMInformation = s00.RIMInformation(val_riminformation)
	if opt_rimroutingaddress {
		toleranceMark_rimroutingaddress := bb.EnterComponent("RIMRoutingAddress")
		var dec_rimroutingaddress RIMRoutingAddress
		if err := dec_rimroutingaddress.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RIMRoutingAddress")
		}
		if err := aper.ChargeValue(bb, dec_rimroutingaddress); err != nil {
			return err
		}
		v.RIMRoutingAddress = &dec_rimroutingaddress
		bb.LeaveComponent(toleranceMark_rimroutingaddress)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s10.RIMTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.RIMTransferExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s10.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RIMRoutingAddress to APER format.
func (v *RIMRoutingAddress) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *RIMRoutingAddress) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "RIMRoutingAddress:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "RIMRoutingAddress:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 2 {
			return fmt.Errorf("%s extension index %d is known to this schema", "RIMRoutingAddress:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "RIMRoutingAddress:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 1 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-1-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.RIMRoutingAddressChoiceTargetRNCID:
			if v.TargetRNCID == nil {
				return fmt.Errorf("choice alternative targetRNC-ID is nil")
			}
			if err := v.TargetRNCID.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding targetRNC-ID: %w", err)
			}
		case s00.RIMRoutingAddressChoiceEHRPDSectorID:
			if err := aper.EncodeOctetStringAligned(inner, v.EHRPDSectorID, 16, 16, true); err != nil {
				return fmt.Errorf("encoding eHRPD-Sector-ID: %w", err)
			}
		default:
			return fmt.Errorf("unknown RIMRoutingAddress extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s07.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	switch v.Choice {
	case s00.RIMRoutingAddressChoiceGERANCellID:
		if v.GERANCellID == nil {
			return fmt.Errorf("choice alternative gERAN-Cell-ID is nil")
		}
		if err := s18.BridgeGERANCellIDMethodMarshalAPERTo(v.GERANCellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding gERAN-Cell-ID: %w", err)
		}
	default:
		return fmt.Errorf("unknown RIMRoutingAddress choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes RIMRoutingAddress from APER format.
func (v *RIMRoutingAddress) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RIMRoutingAddress with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RIMRoutingAddress) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RIMRoutingAddress")
	}
	bb.EnterComponent("RIMRoutingAddress")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RIMRoutingAddress")
	}
	padding, err := aper.CaptureFinalBits(bb, "RIMRoutingAddress")
	if err != nil {
		return runtime.WrapDecodePath(err, "RIMRoutingAddress")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *RIMRoutingAddress) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RIMRoutingAddress{}
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
		if extIdx >= 2 {
			if err := openExtension.ObserveUnknown(bb); err != nil {
				return err
			}
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(1) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 1 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.RIMRoutingAddressChoiceTargetRNCID:
			extensionPath = "TargetRNCID"
			toleranceMark_targetrncid := inner.EnterComponent("TargetRNCID")
			var dec_targetrncid TargetRNCID
			if err := dec_targetrncid.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TargetRNCID")
			}
			if err := aper.ChargeValue(inner, dec_targetrncid); err != nil {
				return err
			}
			v.TargetRNCID = &dec_targetrncid
			inner.LeaveComponent(toleranceMark_targetrncid)
		case s00.RIMRoutingAddressChoiceEHRPDSectorID:
			extensionPath = "EHRPDSectorID"
			val_ehrpdsectorid, err := aper.DecodeOctetStringAligned(inner, 16, 16, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EHRPDSectorID")
			}
			tmp_ehrpdsectorid := val_ehrpdsectorid
			v.EHRPDSectorID = tmp_ehrpdsectorid
		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	v.Choice = 1
	switch v.Choice {
	case s00.RIMRoutingAddressChoiceGERANCellID:
		toleranceMark_gerancellid := bb.EnterComponent("GERANCellID")
		var dec_gerancellid s18.GERANCellID
		if err := s18.BridgeGERANCellIDMethodUnmarshalAPERFrom(&dec_gerancellid, bb); err != nil {
			return runtime.WrapDecodePath(err, "GERANCellID")
		}
		if err := aper.ChargeValue(bb, dec_gerancellid); err != nil {
			return err
		}
		v.GERANCellID = &dec_gerancellid
		bb.LeaveComponent(toleranceMark_gerancellid)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TargetID to APER format.
func (v *TargetID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *TargetID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "TargetID:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "TargetID:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "TargetID:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "TargetID:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 3 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-3-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.TargetIDChoiceTargetgNgRanNodeID:
			if v.TargetgNgRanNodeID == nil {
				return fmt.Errorf("choice alternative targetgNgRanNode-ID is nil")
			}
			if err := v.TargetgNgRanNodeID.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding targetgNgRanNode-ID: %w", err)
			}
		default:
			return fmt.Errorf("unknown TargetID extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s07.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.TargetIDChoiceTargeteNBID:
		if v.TargeteNBID == nil {
			return fmt.Errorf("choice alternative targeteNB-ID is nil")
		}
		if err := v.TargeteNBID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding targeteNB-ID: %w", err)
		}
	case s00.TargetIDChoiceTargetRNCID:
		if v.TargetRNCID == nil {
			return fmt.Errorf("choice alternative targetRNC-ID is nil")
		}
		if err := v.TargetRNCID.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding targetRNC-ID: %w", err)
		}
	case s00.TargetIDChoiceCGI:
		if v.CGI == nil {
			return fmt.Errorf("choice alternative cGI is nil")
		}
		if err := s14.BridgeCGIMethodMarshalAPERTo(v.CGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding cGI: %w", err)
		}
	default:
		return fmt.Errorf("unknown TargetID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes TargetID from APER format.
func (v *TargetID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TargetID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TargetID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TargetID")
	}
	bb.EnterComponent("TargetID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargetID")
	}
	padding, err := aper.CaptureFinalBits(bb, "TargetID")
	if err != nil {
		return runtime.WrapDecodePath(err, "TargetID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *TargetID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetID{}
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
		if extIdx >= 1 {
			if err := openExtension.ObserveUnknown(bb); err != nil {
				return err
			}
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(3) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 3 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.TargetIDChoiceTargetgNgRanNodeID:
			extensionPath = "TargetgNgRanNodeID"
			toleranceMark_targetgngrannodeid := inner.EnterComponent("TargetgNgRanNodeID")
			var dec_targetgngrannodeid TargetNgRanNodeID
			if err := dec_targetgngrannodeid.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TargetgNgRanNodeID")
			}
			if err := aper.ChargeValue(inner, dec_targetgngrannodeid); err != nil {
				return err
			}
			v.TargetgNgRanNodeID = &dec_targetgngrannodeid
			inner.LeaveComponent(toleranceMark_targetgngrannodeid)
		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.TargetIDChoiceTargeteNBID:
		toleranceMark_targetenbid := bb.EnterComponent("TargeteNBID")
		var dec_targetenbid TargeteNBID
		if err := dec_targetenbid.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TargeteNBID")
		}
		if err := aper.ChargeValue(bb, dec_targetenbid); err != nil {
			return err
		}
		v.TargeteNBID = &dec_targetenbid
		bb.LeaveComponent(toleranceMark_targetenbid)
	case s00.TargetIDChoiceTargetRNCID:
		toleranceMark_targetrncid := bb.EnterComponent("TargetRNCID")
		var dec_targetrncid TargetRNCID
		if err := dec_targetrncid.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "TargetRNCID")
		}
		if err := aper.ChargeValue(bb, dec_targetrncid); err != nil {
			return err
		}
		v.TargetRNCID = &dec_targetrncid
		bb.LeaveComponent(toleranceMark_targetrncid)
	case s00.TargetIDChoiceCGI:
		toleranceMark_cgi := bb.EnterComponent("CGI")
		var dec_cgi s14.CGI
		if err := s14.BridgeCGIMethodUnmarshalAPERFrom(&dec_cgi, bb); err != nil {
			return runtime.WrapDecodePath(err, "CGI")
		}
		if err := aper.ChargeValue(bb, dec_cgi); err != nil {
			return err
		}
		v.CGI = &dec_cgi
		bb.LeaveComponent(toleranceMark_cgi)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TargeteNBID to APER format.
func (v *TargeteNBID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TargeteNBID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s18.BridgeGlobalENBIDMethodMarshalAPERTo(&v.GlobalENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-ENB-ID: %w", err)
	}
	if err := s32.BridgeTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TargeteNBID from APER format.
func (v *TargeteNBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TargeteNBID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TargeteNBID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBID")
	}
	bb.EnterComponent("TargeteNBID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBID")
	}
	padding, err := aper.CaptureFinalBits(bb, "TargeteNBID")
	if err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TargeteNBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBID{}
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
	toleranceMark_globalenbid := bb.EnterComponent("GlobalENBID")
	if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&v.GlobalENBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	bb.LeaveComponent(toleranceMark_globalenbid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TargeteNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargeteNBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TargetRNCID to APER format.
func (v *TargetRNCID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TargetRNCID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.RAC != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ExtendedRNCID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s18.BridgeLAIMethodMarshalAPERTo(&v.LAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding lAI: %w", err)
	}
	if v.RAC != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.RAC), 1, 1, true); err != nil {
			return fmt.Errorf("encoding rAC: %w", err)
		}
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.RNCID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false); err != nil {
		return fmt.Errorf("encoding rNC-ID: %w", err)
	}
	if v.ExtendedRNCID != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ExtendedRNCID), s07.BridgeInt64Ptr(4096), s07.BridgeInt64Ptr(65535), false); err != nil {
			return fmt.Errorf("encoding extendedRNC-ID: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TargetRNCID from APER format.
func (v *TargetRNCID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TargetRNCID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TargetRNCID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TargetRNCID")
	}
	bb.EnterComponent("TargetRNCID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargetRNCID")
	}
	padding, err := aper.CaptureFinalBits(bb, "TargetRNCID")
	if err != nil {
		return runtime.WrapDecodePath(err, "TargetRNCID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TargetRNCID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetRNCID{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_rac, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_extendedrncid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_lai := bb.EnterComponent("LAI")
	if err := s18.BridgeLAIMethodUnmarshalAPERFrom(&v.LAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "LAI")
	}
	bb.LeaveComponent(toleranceMark_lai)
	if opt_rac {
		val_rac, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "RAC")
		}
		tmp_rac := s00.RAC(val_rac)
		if err := aper.ChargeValue(bb, tmp_rac); err != nil {
			return err
		}
		v.RAC = &tmp_rac
	}
	val_rncid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RNCID")
	}
	v.RNCID = s00.RNCID(val_rncid)
	if opt_extendedrncid {
		val_extendedrncid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(4096), s07.BridgeInt64Ptr(65535), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtendedRNCID")
		}
		tmp_extendedrncid := s00.ExtendedRNCID(val_extendedrncid)
		if err := aper.ChargeValue(bb, tmp_extendedrncid); err != nil {
			return err
		}
		v.ExtendedRNCID = (*s00.ExtendedRNCID)(bb.OwnInt64(int64(tmp_extendedrncid)))

	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TargetRNCIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargetRNCIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TargetNgRanNodeID to APER format.
func (v *TargetNgRanNodeID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TargetNgRanNodeID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERTo(&v.GlobalRANNODEID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-RAN-NODE-ID: %w", err)
	}
	if err := s18.BridgeFiveGSTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TargetNgRanNodeID from APER format.
func (v *TargetNgRanNodeID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TargetNgRanNodeID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TargetNgRanNodeID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TargetNgRanNodeID")
	}
	bb.EnterComponent("TargetNgRanNodeID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TargetNgRanNodeID")
	}
	padding, err := aper.CaptureFinalBits(bb, "TargetNgRanNodeID")
	if err != nil {
		return runtime.WrapDecodePath(err, "TargetNgRanNodeID")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TargetNgRanNodeID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargetNgRanNodeID{}
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
	toleranceMark_globalrannodeid := bb.EnterComponent("GlobalRANNODEID")
	if err := s19.BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(&v.GlobalRANNODEID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalRANNODEID")
	}
	bb.LeaveComponent(toleranceMark_globalrannodeid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s18.BridgeFiveGSTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TargetNgRanNodeIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargetNgRanNodeIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *InformationOnRecommendedCellsAndENBsForPaging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InformationOnRecommendedCellsAndENBsForPaging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InformationOnRecommendedCellsAndENBsForPaging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InformationOnRecommendedCellsAndENBsForPaging) WithoutReplay() InformationOnRecommendedCellsAndENBsForPaging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InformationOnRecommendedCellsAndENBsForPaging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RIMRoutingAddress) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RIMRoutingAddress", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RIMRoutingAddress", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RIMRoutingAddress) WithoutReplay() RIMRoutingAddress {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RIMRoutingAddress
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RIMTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RIMTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RIMTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RIMTransfer) WithoutReplay() RIMTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RIMTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TargetID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargetID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TargetID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TargetID) WithoutReplay() TargetID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TargetID
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TargetNgRanNodeID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargetNgRanNodeID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TargetNgRanNodeID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TargetNgRanNodeID) WithoutReplay() TargetNgRanNodeID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TargetNgRanNodeID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TargetRNCID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargetRNCID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TargetRNCID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TargetRNCID) WithoutReplay() TargetRNCID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TargetRNCID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TargeteNBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargeteNBID", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TargeteNBID", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TargeteNBID) WithoutReplay() TargeteNBID {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TargeteNBID
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *InformationOnRecommendedCellsAndENBsForPaging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InformationOnRecommendedCellsAndENBsForPaging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InformationOnRecommendedCellsAndENBsForPaging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InformationOnRecommendedCellsAndENBsForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InformationOnRecommendedCellsAndENBsForPaging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InformationOnRecommendedCellsAndENBsForPaging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InformationOnRecommendedCellsAndENBsForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RIMTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RIMTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RIMTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RIMTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RIMTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RIMTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RIMTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TargetNgRanNodeID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TargetNgRanNodeID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargetNgRanNodeID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargetNgRanNodeID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TargetNgRanNodeID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargetNgRanNodeID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargetNgRanNodeID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TargetRNCID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TargetRNCID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargetRNCID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargetRNCID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TargetRNCID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargetRNCID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargetRNCID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TargeteNBID) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TargeteNBID) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargeteNBID.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargeteNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TargeteNBID) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TargeteNBID.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TargeteNBID.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InformationOnRecommendedCellsAndENBsForPaging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InformationOnRecommendedCellsAndENBsForPaging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InformationOnRecommendedCellsAndENBsForPaging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InformationOnRecommendedCellsAndENBsForPaging")
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InformationOnRecommendedCellsAndENBsForPaging")
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInformationOnRecommendedCellsAndENBsForPaging(v, &s)
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
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InformationOnRecommendedCellsAndENBsForPaging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RIMRoutingAddress) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RIMRoutingAddress")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RIMRoutingAddress) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RIMRoutingAddress")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRIMRoutingAddress(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RIMRoutingAddress")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RIMRoutingAddress")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RIMRoutingAddress) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RIMRoutingAddress")
}
func (v *RIMRoutingAddress) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RIMRoutingAddress")
}
func (v *RIMRoutingAddress) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRIMRoutingAddress(v, &s)
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
func (v *RIMRoutingAddress) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RIMRoutingAddress) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RIMTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RIMTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RIMTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RIMTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRIMTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RIMTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RIMTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RIMTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RIMTransfer")
}
func (v *RIMTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RIMTransfer")
}
func (v *RIMTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRIMTransfer(v, &s)
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
func (v *RIMTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RIMTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TargetID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TargetID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TargetID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TargetID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTargetID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TargetID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TargetID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TargetID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TargetID")
}
func (v *TargetID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TargetID")
}
func (v *TargetID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTargetID(v, &s)
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
func (v *TargetID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TargetID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TargetNgRanNodeID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TargetNgRanNodeID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TargetNgRanNodeID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TargetNgRanNodeID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTargetNgRanNodeID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TargetNgRanNodeID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TargetNgRanNodeID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TargetNgRanNodeID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TargetNgRanNodeID")
}
func (v *TargetNgRanNodeID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TargetNgRanNodeID")
}
func (v *TargetNgRanNodeID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTargetNgRanNodeID(v, &s)
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
func (v *TargetNgRanNodeID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TargetNgRanNodeID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TargetRNCID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TargetRNCID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TargetRNCID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TargetRNCID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTargetRNCID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TargetRNCID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TargetRNCID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TargetRNCID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TargetRNCID")
}
func (v *TargetRNCID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TargetRNCID")
}
func (v *TargetRNCID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTargetRNCID(v, &s)
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
func (v *TargetRNCID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TargetRNCID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TargeteNBID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TargeteNBID")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TargeteNBID) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TargeteNBID")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTargeteNBID(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TargeteNBID")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TargeteNBID")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TargeteNBID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TargeteNBID")
}
func (v *TargeteNBID) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TargeteNBID")
}
func (v *TargeteNBID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTargeteNBID(v, &s)
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
func (v *TargeteNBID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TargeteNBID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InformationOnRecommendedCellsAndENBsForPaging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InformationOnRecommendedCellsAndENBsForPaging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InformationOnRecommendedCellsAndENBsForPaging{}
		return report, aper.OperationError(err, "InformationOnRecommendedCellsAndENBsForPaging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InformationOnRecommendedCellsAndENBsForPaging")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RIMRoutingAddress) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RIMRoutingAddress")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RIMRoutingAddress
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRIMRoutingAddress(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RIMRoutingAddress{}
		return report, aper.OperationError(err, "RIMRoutingAddress")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RIMRoutingAddress")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RIMTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RIMTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RIMTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRIMTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RIMTransfer{}
		return report, aper.OperationError(err, "RIMTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RIMTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TargetID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TargetID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TargetID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTargetID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TargetID{}
		return report, aper.OperationError(err, "TargetID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TargetID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TargetNgRanNodeID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TargetNgRanNodeID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TargetNgRanNodeID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTargetNgRanNodeID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TargetNgRanNodeID{}
		return report, aper.OperationError(err, "TargetNgRanNodeID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TargetNgRanNodeID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TargetRNCID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TargetRNCID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TargetRNCID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTargetRNCID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TargetRNCID{}
		return report, aper.OperationError(err, "TargetRNCID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TargetRNCID")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TargeteNBID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TargeteNBID")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TargeteNBID
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTargeteNBID(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TargeteNBID{}
		return report, aper.OperationError(err, "TargeteNBID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TargeteNBID")
}

// NewRIMRoutingAddressGERANCellID constructs a checked complete value.
func NewRIMRoutingAddressGERANCellID(v s18.GERANCellID, options ...aper.BuildOption) (RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	value := BridgeNewRIMRoutingAddressGERANCellIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressGERANCellID")
}

// NewRIMRoutingAddressTargetRNCID constructs a checked complete value.
func NewRIMRoutingAddressTargetRNCID(v TargetRNCID, options ...aper.BuildOption) (RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	value := BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressTargetRNCID")
}

// NewRIMRoutingAddressEHRPDSectorID constructs a checked complete value.
func NewRIMRoutingAddressEHRPDSectorID(v []byte, options ...aper.BuildOption) (RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	value := BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressEHRPDSectorID")
}

// NewRIMRoutingAddressUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewRIMRoutingAddressUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressUnknownExtension")
	}
	value := RIMRoutingAddress{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressUnknownExtension")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressUnknownExtension")
}

// NewTargetIDUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewTargetIDUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDUnknownExtension")
	}
	value := TargetID{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDUnknownExtension")
	}
	return value, aper.OperationError(nil, "TargetIDUnknownExtension")
}

type TAIList = []TAIItemIEValueProtocolIESingleContainer

// TAIItem represents the ASN.1 type TAIItem (SEQUENCE).
type TAIItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	TAI               s32.TAI                       `asn1:"tag:0,context,implicit"`
	IEExtensions      s11.TAIItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                          `asn1:"-" json:"-"`
	extCount          int64                         `asn1:"-" json:"-"`
	extPresent        []bool                        `asn1:"-" json:"-"`
	extData           [][]byte                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// ENBDirectInformationTransfer represents the ASN.1 type ENBDirectInformationTransfer (SEQUENCE).
type ENBDirectInformationTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ENBDirectInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// InterSystemInformationTransferType represents the ASN.1 CHOICE type Inter-SystemInformationTransferType.
type InterSystemInformationTransferType struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	RIMTransfer        *RIMTransfer          `json:"RIMTransfer,omitempty"`
}

// NewInterSystemInformationTransferTypeRIMTransfer creates a InterSystemInformationTransferType with the rIMTransfer alternative.
func BridgeNewInterSystemInformationTransferTypeRIMTransferLegacy(v RIMTransfer) InterSystemInformationTransferType {
	return InterSystemInformationTransferType{
		Choice:      s00.InterSystemInformationTransferTypeChoiceRIMTransfer,
		RIMTransfer: &v,
	}
}

// MMEDirectInformationTransfer represents the ASN.1 type MMEDirectInformationTransfer (SEQUENCE).
type MMEDirectInformationTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      MMEDirectInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}
type BridgeAsn1cAPERTAIListListValue struct{ Value TAIList }

// MarshalAPERTAIListTo appends a TAIList list to bb.
func BridgeMarshalAPERTAIListTo(list TAIList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERTAIListListValue{Value: list}
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

// MarshalAPER encodes TAIItem to APER format.
func (v *TAIItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TAIItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s32.BridgeTAIMethodMarshalAPERTo(&v.TAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding tAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTAIItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TAIItem from APER format.
func (v *TAIItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIItem")
	}
	bb.EnterComponent("TAIItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TAIItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TAIItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TAIItem{}
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
	toleranceMark_tai := bb.EnterComponent("TAI")
	if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&v.TAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	bb.LeaveComponent(toleranceMark_tai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TAIItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ENBDirectInformationTransfer to APER format.
func (v *ENBDirectInformationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBDirectInformationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ENBDirectInformationTransfer from APER format.
func (v *ENBDirectInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBDirectInformationTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBDirectInformationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBDirectInformationTransfer")
	}
	bb.EnterComponent("ENBDirectInformationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBDirectInformationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBDirectInformationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBDirectInformationTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBDirectInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBDirectInformationTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ENBDirectInformationTransferIEField
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

// MarshalAPER encodes InterSystemInformationTransferType to APER format.
func (v *InterSystemInformationTransferType) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InterSystemInformationTransferType) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "InterSystemInformationTransferType:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "InterSystemInformationTransferType:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "InterSystemInformationTransferType:", v.Choice)
	}
	isExtension := v.Choice > 1
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "InterSystemInformationTransferType:", v.Choice)
	}
	switch v.Choice {
	case s00.InterSystemInformationTransferTypeChoiceRIMTransfer:
		if v.RIMTransfer == nil {
			return fmt.Errorf("choice alternative rIMTransfer is nil")
		}
		if err := v.RIMTransfer.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding rIMTransfer: %w", err)
		}
	default:
		return fmt.Errorf("unknown InterSystemInformationTransferType choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes InterSystemInformationTransferType from APER format.
func (v *InterSystemInformationTransferType) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterSystemInformationTransferType with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterSystemInformationTransferType) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
	}
	bb.EnterComponent("InterSystemInformationTransferType")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterSystemInformationTransferType")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InterSystemInformationTransferType) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterSystemInformationTransferType{}
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
	v.Choice = 1
	switch v.Choice {
	case s00.InterSystemInformationTransferTypeChoiceRIMTransfer:
		toleranceMark_rimtransfer := bb.EnterComponent("RIMTransfer")
		var dec_rimtransfer RIMTransfer
		if err := dec_rimtransfer.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "RIMTransfer")
		}
		if err := aper.ChargeValue(bb, dec_rimtransfer); err != nil {
			return err
		}
		v.RIMTransfer = &dec_rimtransfer
		bb.LeaveComponent(toleranceMark_rimtransfer)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes MMEDirectInformationTransfer to APER format.
func (v *MMEDirectInformationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEDirectInformationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes MMEDirectInformationTransfer from APER format.
func (v *MMEDirectInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEDirectInformationTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEDirectInformationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEDirectInformationTransfer")
	}
	bb.EnterComponent("MMEDirectInformationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEDirectInformationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEDirectInformationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEDirectInformationTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEDirectInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEDirectInformationTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(MMEDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem MMEDirectInformationTransferIEField
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
func (v *ENBDirectInformationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBDirectInformationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBDirectInformationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBDirectInformationTransfer) WithoutReplay() ENBDirectInformationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBDirectInformationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterSystemInformationTransferType) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemInformationTransferType", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InterSystemInformationTransferType", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterSystemInformationTransferType) WithoutReplay() InterSystemInformationTransferType {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InterSystemInformationTransferType
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEDirectInformationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEDirectInformationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEDirectInformationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEDirectInformationTransfer) WithoutReplay() MMEDirectInformationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEDirectInformationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIItem", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIItem", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIItem) WithoutReplay() TAIItem {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBDirectInformationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBDirectInformationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBDirectInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBDirectInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBDirectInformationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBDirectInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBDirectInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEDirectInformationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEDirectInformationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEDirectInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEDirectInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEDirectInformationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEDirectInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEDirectInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TAIItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TAIItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TAIItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TAIItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TAIItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBDirectInformationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBDirectInformationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBDirectInformationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBDirectInformationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBDirectInformationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBDirectInformationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBDirectInformationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBDirectInformationTransfer")
}
func (v *ENBDirectInformationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBDirectInformationTransfer")
}
func (v *ENBDirectInformationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBDirectInformationTransfer(v, &s)
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
func (v *ENBDirectInformationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBDirectInformationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *InterSystemInformationTransferType) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InterSystemInformationTransferType")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InterSystemInformationTransferType) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterSystemInformationTransferType")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInterSystemInformationTransferType(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InterSystemInformationTransferType")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InterSystemInformationTransferType")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InterSystemInformationTransferType) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InterSystemInformationTransferType")
}
func (v *InterSystemInformationTransferType) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InterSystemInformationTransferType")
}
func (v *InterSystemInformationTransferType) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInterSystemInformationTransferType(v, &s)
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
func (v *InterSystemInformationTransferType) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InterSystemInformationTransferType) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEDirectInformationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEDirectInformationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEDirectInformationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEDirectInformationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEDirectInformationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEDirectInformationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEDirectInformationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEDirectInformationTransfer")
}
func (v *MMEDirectInformationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEDirectInformationTransfer")
}
func (v *MMEDirectInformationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEDirectInformationTransfer(v, &s)
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
func (v *MMEDirectInformationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEDirectInformationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIItem")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIItem) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIItem")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIItem(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIItem")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIItem")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIItem")
}
func (v *TAIItem) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIItem")
}
func (v *TAIItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIItem(v, &s)
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
func (v *TAIItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBDirectInformationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBDirectInformationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBDirectInformationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBDirectInformationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBDirectInformationTransfer{}
		return report, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBDirectInformationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InterSystemInformationTransferType) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterSystemInformationTransferType")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InterSystemInformationTransferType
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInterSystemInformationTransferType(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InterSystemInformationTransferType{}
		return report, aper.OperationError(err, "InterSystemInformationTransferType")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterSystemInformationTransferType")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEDirectInformationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEDirectInformationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEDirectInformationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEDirectInformationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEDirectInformationTransfer{}
		return report, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEDirectInformationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIItem")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIItem
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIItem{}
		return report, aper.OperationError(err, "TAIItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIItem")
}

// NewInterSystemInformationTransferTypeRIMTransfer constructs a checked complete value.
func NewInterSystemInformationTransferTypeRIMTransfer(v RIMTransfer, options ...aper.BuildOption) (InterSystemInformationTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	value := BridgeNewInterSystemInformationTransferTypeRIMTransferLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	return value, aper.OperationError(nil, "InterSystemInformationTransferTypeRIMTransfer")
}

// NewInterSystemInformationTransferTypeUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewInterSystemInformationTransferTypeUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (InterSystemInformationTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeUnknownExtension")
	}
	value := InterSystemInformationTransferType{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeUnknownExtension")
	}
	return value, aper.OperationError(nil, "InterSystemInformationTransferTypeUnknownExtension")
}

type ENBDirectInformationTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowInterSystemInformationTransferTypeEDT *InterSystemInformationTransferType
}

func (v ENBDirectInformationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(121):
		return v.rowInterSystemInformationTransferTypeEDT != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBDirectInformationTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBDirectInformationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBDirectInformationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBDirectInformationTransferIEs"}}
}
func (ENBDirectInformationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(121):
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

// AsInterSystemInformationTransferTypeEDT returns the selected InterSystemInformationTransferTypeEDT value of ENBDirectInformationTransferIEValue and reports whether that alternative is active.
func (v *ENBDirectInformationTransferIEValue) AsInterSystemInformationTransferTypeEDT() (*InterSystemInformationTransferType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(121) || v.rowInterSystemInformationTransferTypeEDT == nil {
		return nil, false
	}
	return v.rowInterSystemInformationTransferTypeEDT, true
}
func (v ENBDirectInformationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBDirectInformationTransferIEValue, error) {
	out := ENBDirectInformationTransferIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(121):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value InterSystemInformationTransferType
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "InterSystemInformationTransferTypeEDT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InterSystemInformationTransferType")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowInterSystemInformationTransferTypeEDT = &value
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
func (v ENBDirectInformationTransferIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ENBDirectInformationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(121):
		if v.rowInterSystemInformationTransferTypeEDT == nil {
			return nil, fmt.Errorf("%s missing value", "ENBDirectInformationTransferIEs.id-Inter-SystemInformationTransferTypeEDT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowInterSystemInformationTransferTypeEDT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBDirectInformationTransferIEValue:", v.id)
	}
}

type HandoverRequiredIEValue struct {
	id                                             s00.ProtocolIEID
	received                                       aper.WireSpan
	replay                                         aper.Snapshot
	opaque                                         aper.OpaqueOpenType
	isOpaque                                       bool
	rowMMEUES1APID                                 *s00.MMEUES1APID
	rowENBUES1APID                                 *s00.ENBUES1APID
	rowHandoverType                                *s00.HandoverType
	rowCause                                       *s14.Cause
	rowTargetID                                    *TargetID
	rowDirectForwardingPathAvailability            *s00.DirectForwardingPathAvailability
	rowSRVCCHOIndication                           *s00.SRVCCHOIndication
	rowSourceToTargetTransparentContainer          *s00.SourceToTargetTransparentContainer
	rowSourceToTargetTransparentContainerSecondary *s00.SourceToTargetTransparentContainer
	rowMSClassmark2                                *s00.MSClassmark2
	rowMSClassmark3                                *s00.MSClassmark3
	rowCSGId                                       *s00.CSGId
	rowCellAccessMode                              *s00.CellAccessMode
	rowPSServiceNotAvailable                       *s00.PSServiceNotAvailable
}

func (v HandoverRequiredIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(1):
		return v.rowHandoverType != nil
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(4):
		return v.rowTargetID != nil
	case s00.ProtocolIEID(79):
		return v.rowDirectForwardingPathAvailability != nil
	case s00.ProtocolIEID(125):
		return v.rowSRVCCHOIndication != nil
	case s00.ProtocolIEID(104):
		return v.rowSourceToTargetTransparentContainer != nil
	case s00.ProtocolIEID(138):
		return v.rowSourceToTargetTransparentContainerSecondary != nil
	case s00.ProtocolIEID(132):
		return v.rowMSClassmark2 != nil
	case s00.ProtocolIEID(133):
		return v.rowMSClassmark3 != nil
	case s00.ProtocolIEID(127):
		return v.rowCSGId != nil
	case s00.ProtocolIEID(145):
		return v.rowCellAccessMode != nil
	case s00.ProtocolIEID(150):
		return v.rowPSServiceNotAvailable != nil
	}
	return false
}

// Opaque returns the retained opaque open value of HandoverRequiredIEValue and reports whether the opaque alternative is selected.
func (v *HandoverRequiredIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverRequiredIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs"}}
}
func (HandoverRequiredIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(4):
		return aper.UnknownSelector
	case s00.ProtocolIEID(79):
		return aper.UnknownSelector
	case s00.ProtocolIEID(125):
		return aper.UnknownSelector
	case s00.ProtocolIEID(104):
		return aper.UnknownSelector
	case s00.ProtocolIEID(138):
		return aper.UnknownSelector
	case s00.ProtocolIEID(132):
		return aper.UnknownSelector
	case s00.ProtocolIEID(133):
		return aper.UnknownSelector
	case s00.ProtocolIEID(127):
		return aper.UnknownSelector
	case s00.ProtocolIEID(145):
		return aper.UnknownSelector
	case s00.ProtocolIEID(150):
		return aper.UnknownSelector
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
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsHandoverType returns the selected HandoverType value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsHandoverType() (*s00.HandoverType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowHandoverType == nil {
		return nil, false
	}
	return v.rowHandoverType, true
}

// AsCause returns the selected Cause value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsTargetID returns the selected TargetID value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsTargetID() (*TargetID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(4) || v.rowTargetID == nil {
		return nil, false
	}
	return v.rowTargetID, true
}

// AsDirectForwardingPathAvailability returns the selected DirectForwardingPathAvailability value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsDirectForwardingPathAvailability() (*s00.DirectForwardingPathAvailability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(79) || v.rowDirectForwardingPathAvailability == nil {
		return nil, false
	}
	return v.rowDirectForwardingPathAvailability, true
}

// AsSRVCCHOIndication returns the selected SRVCCHOIndication value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsSRVCCHOIndication() (*s00.SRVCCHOIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(125) || v.rowSRVCCHOIndication == nil {
		return nil, false
	}
	return v.rowSRVCCHOIndication, true
}

// AsSourceToTargetTransparentContainer returns the selected SourceToTargetTransparentContainer value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsSourceToTargetTransparentContainer() (*s00.SourceToTargetTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(104) || v.rowSourceToTargetTransparentContainer == nil {
		return nil, false
	}
	return v.rowSourceToTargetTransparentContainer, true
}

// AsSourceToTargetTransparentContainerSecondary returns the selected SourceToTargetTransparentContainerSecondary value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsSourceToTargetTransparentContainerSecondary() (*s00.SourceToTargetTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(138) || v.rowSourceToTargetTransparentContainerSecondary == nil {
		return nil, false
	}
	return v.rowSourceToTargetTransparentContainerSecondary, true
}

// AsMSClassmark2 returns the selected MSClassmark2 value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsMSClassmark2() (*s00.MSClassmark2, bool) {
	if v == nil || v.id != s00.ProtocolIEID(132) || v.rowMSClassmark2 == nil {
		return nil, false
	}
	return v.rowMSClassmark2, true
}

// AsMSClassmark3 returns the selected MSClassmark3 value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsMSClassmark3() (*s00.MSClassmark3, bool) {
	if v == nil || v.id != s00.ProtocolIEID(133) || v.rowMSClassmark3 == nil {
		return nil, false
	}
	return v.rowMSClassmark3, true
}

// AsCSGId returns the selected CSGId value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}

// AsCellAccessMode returns the selected CellAccessMode value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}

// AsPSServiceNotAvailable returns the selected PSServiceNotAvailable value of HandoverRequiredIEValue and reports whether that alternative is active.
func (v *HandoverRequiredIEValue) AsPSServiceNotAvailable() (*s00.PSServiceNotAvailable, bool) {
	if v == nil || v.id != s00.ProtocolIEID(150) || v.rowPSServiceNotAvailable == nil {
		return nil, false
	}
	return v.rowPSServiceNotAvailable, true
}
func (v HandoverRequiredIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverRequiredIEValue, error) {
	out := HandoverRequiredIEValue{id: id}
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
	case s00.ProtocolIEID(1):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 2, Path: "HandoverType"})
		value := s00.HandoverType(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "HandoverType:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowHandoverType = &value
		raw.RetainContents(&out.received)
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
	case s00.ProtocolIEID(4):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TargetID
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TargetID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TargetID")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTargetID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(79):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DirectForwardingPathAvailability"})
		value := s00.DirectForwardingPathAvailability(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DirectForwardingPathAvailability:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDirectForwardingPathAvailability = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(125):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCHOIndication"})
		value := s00.SRVCCHOIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCHOIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCHOIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(104):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SourceToTargetTransparentContainer, error) {
			var v struct {
				Value s00.SourceToTargetTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.SourceToTargetTransparentContainer(val_value)
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
		out.rowSourceToTargetTransparentContainer = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(138):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SourceToTargetTransparentContainer, error) {
			var v struct {
				Value s00.SourceToTargetTransparentContainer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.SourceToTargetTransparentContainer(val_value)
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
		out.rowSourceToTargetTransparentContainerSecondary = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(132):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MSClassmark2, error) {
			var v struct{ Value s00.MSClassmark2 }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.MSClassmark2(val_value)
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
		out.rowMSClassmark2 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(133):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MSClassmark3, error) {
			var v struct{ Value s00.MSClassmark3 }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.MSClassmark3(val_value)
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
		out.rowMSClassmark3 = &value
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
	case s00.ProtocolIEID(150):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PSServiceNotAvailable"})
		value := s00.PSServiceNotAvailable(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PSServiceNotAvailable:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPSServiceNotAvailable = &value
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
func (v HandoverRequiredIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v HandoverRequiredIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(1):
		if v.rowHandoverType == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-HandoverType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowHandoverType), 5, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(4):
		if v.rowTargetID == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-TargetID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTargetID.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(79):
		if v.rowDirectForwardingPathAvailability == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-Direct-Forwarding-Path-Availability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowDirectForwardingPathAvailability), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(125):
		if v.rowSRVCCHOIndication == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-SRVCCHOIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCHOIndication), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(104):
		if v.rowSourceToTargetTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-Source-ToTarget-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SourceToTargetTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.SourceToTargetTransparentContainer
			}{Value: value}
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
		})(*v.rowSourceToTargetTransparentContainer, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(138):
		if v.rowSourceToTargetTransparentContainerSecondary == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-Source-ToTarget-TransparentContainer-Secondary:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SourceToTargetTransparentContainer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.SourceToTargetTransparentContainer
			}{Value: value}
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
		})(*v.rowSourceToTargetTransparentContainerSecondary, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(132):
		if v.rowMSClassmark2 == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-MSClassmark2:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MSClassmark2, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MSClassmark2 }{Value: value}
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
		})(*v.rowMSClassmark2, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(133):
		if v.rowMSClassmark3 == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-MSClassmark3:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MSClassmark3, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MSClassmark3 }{Value: value}
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
		})(*v.rowMSClassmark3, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(127):
		if v.rowCSGId == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-CSG-Id:")
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
	case s00.ProtocolIEID(145):
		if v.rowCellAccessMode == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-CellAccessMode:")
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
	case s00.ProtocolIEID(150):
		if v.rowPSServiceNotAvailable == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRequiredIEs.id-PS-ServiceNotAvailable:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPSServiceNotAvailable), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverRequiredIEValue:", v.id)
	}
}

type MMEDirectInformationTransferIEValue struct {
	id                                       s00.ProtocolIEID
	received                                 aper.WireSpan
	replay                                   aper.Snapshot
	opaque                                   aper.OpaqueOpenType
	isOpaque                                 bool
	rowInterSystemInformationTransferTypeMDT *InterSystemInformationTransferType
}

func (v MMEDirectInformationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(122):
		return v.rowInterSystemInformationTransferTypeMDT != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEDirectInformationTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEDirectInformationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEDirectInformationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEDirectInformationTransferIEs"}}
}
func (MMEDirectInformationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(122):
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

// AsInterSystemInformationTransferTypeMDT returns the selected InterSystemInformationTransferTypeMDT value of MMEDirectInformationTransferIEValue and reports whether that alternative is active.
func (v *MMEDirectInformationTransferIEValue) AsInterSystemInformationTransferTypeMDT() (*InterSystemInformationTransferType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(122) || v.rowInterSystemInformationTransferTypeMDT == nil {
		return nil, false
	}
	return v.rowInterSystemInformationTransferTypeMDT, true
}
func (v MMEDirectInformationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEDirectInformationTransferIEValue, error) {
	out := MMEDirectInformationTransferIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(122):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value InterSystemInformationTransferType
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "InterSystemInformationTransferTypeMDT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InterSystemInformationTransferType")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowInterSystemInformationTransferTypeMDT = &value
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
func (v MMEDirectInformationTransferIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v MMEDirectInformationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(122):
		if v.rowInterSystemInformationTransferTypeMDT == nil {
			return nil, fmt.Errorf("%s missing value", "MMEDirectInformationTransferIEs.id-Inter-SystemInformationTransferTypeMDT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowInterSystemInformationTransferTypeMDT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEDirectInformationTransferIEValue:", v.id)
	}
}

type TAIItemIEValue struct {
	id         s00.ProtocolIEID
	received   aper.WireSpan
	replay     aper.Snapshot
	opaque     aper.OpaqueOpenType
	isOpaque   bool
	rowTAIItem *TAIItem
}

func (v TAIItemIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(47):
		return v.rowTAIItem != nil
	}
	return false
}

// Opaque returns the retained opaque open value of TAIItemIEValue and reports whether the opaque alternative is selected.
func (v *TAIItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (TAIItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIItemIEs"}}
}
func (TAIItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(47):
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

// AsTAIItem returns the selected TAIItem value of TAIItemIEValue and reports whether that alternative is active.
func (v *TAIItemIEValue) AsTAIItem() (*TAIItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(47) || v.rowTAIItem == nil {
		return nil, false
	}
	return v.rowTAIItem, true
}
func (v TAIItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TAIItemIEValue, error) {
	out := TAIItemIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(47):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TAIItem
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TAIItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAIItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTAIItem = &value
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
func (v TAIItemIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v TAIItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(47):
		if v.rowTAIItem == nil {
			return nil, fmt.Errorf("%s missing value", "TAIItemIEs.id-TAIItem:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTAIItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TAIItemIEValue:", v.id)
	}
}

type ENBDirectInformationTransferIETable struct{}

func ENBDirectInformationTransferIEs() ENBDirectInformationTransferIETable {
	return ENBDirectInformationTransferIETable{}
}

// ID returns the ASN.1 object-set identity of ENBDirectInformationTransferIETable.
func (ENBDirectInformationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBDirectInformationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBDirectInformationTransferIETable.
func (ENBDirectInformationTransferIETable) Table() s00.ENBDirectInformationTransferIEValueIETable {
	return func() s00.ENBDirectInformationTransferIEValueIETable {
		sealed := s00.ENBDirectInformationTransferIEValueIETable{}
		*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBDirectInformationTransferIETable) infoInterSystemInformationTransferTypeEDT() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBDirectInformationTransferIEs().ID(), ID: s00.ProtocolIEID(121), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "Inter-SystemInformationTransferType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBDirectInformationTransferIEs", Row: "id-Inter-SystemInformationTransferTypeEDT"}}}
}

// InterSystemInformationTransferTypeEDT returns the typed binding for the InterSystemInformationTransferTypeEDT row of ENBDirectInformationTransferIETable.
func (t ENBDirectInformationTransferIETable) InterSystemInformationTransferTypeEDT() ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding {
	return ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding{info: t.infoInterSystemInformationTransferTypeEDT(), codec: InterSystemInformationTransferTypeValueCodec{path: "InterSystemInformationTransferType",
		decode: func(data []byte, options aper.DecodeState) (InterSystemInformationTransferType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("InterSystemInformationTransferType")
			var zero ENBDirectInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(121), raw)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
			}
			value, ok := decoded.AsInterSystemInformationTransferTypeEDT()
			if !ok {
				var empty InterSystemInformationTransferType
				return empty, fmt.Errorf("binding ENBDirectInformationTransferIEs.id-Inter-SystemInformationTransferTypeEDT: no selected value")
			}
			return *value, nil
		},
		encode: func(value InterSystemInformationTransferType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBDirectInformationTransferIEValue{id: s00.ProtocolIEID(121), rowInterSystemInformationTransferTypeEDT: &value}).encodeFresh(fresh, budget)
		}, capture: func(v InterSystemInformationTransferType, options aper.DecodeState) (InterSystemInformationTransferType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APInterSystemInformationTransferType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v InterSystemInformationTransferType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APInterSystemInformationTransferType(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemInformationTransferType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value InterSystemInformationTransferType) ENBDirectInformationTransferIEValue {
		return ENBDirectInformationTransferIEValue{id: s00.ProtocolIEID(121), rowInterSystemInformationTransferTypeEDT: &value}
	}, get: func(value *ENBDirectInformationTransferIEValue) (*InterSystemInformationTransferType, bool) {
		return value.AsInterSystemInformationTransferTypeEDT()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBDirectInformationTransferIETable.
func (t ENBDirectInformationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBDirectInformationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(121):
		return ENBDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Inter-SystemInformationTransferTypeEDT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBDirectInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBDirectInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBDirectInformationTransferIEField{Id: id, Criticality: criticality, Value: ENBDirectInformationTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type HandoverRequiredIETable struct{}

func HandoverRequiredIEs() HandoverRequiredIETable { return HandoverRequiredIETable{} }

// ID returns the ASN.1 object-set identity of HandoverRequiredIETable.
func (HandoverRequiredIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverRequiredIETable.
func (HandoverRequiredIETable) Table() s00.HandoverRequiredIEValueIETable {
	return func() s00.HandoverRequiredIEValueIETable {
		sealed := s00.HandoverRequiredIEValueIETable{}
		*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverRequiredIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) MMEUES1APID() HandoverRequiredMMEUES1APIDIEBinding {
	return HandoverRequiredMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (HandoverRequiredIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) ENBUES1APID() HandoverRequiredENBUES1APIDIEBinding {
	return HandoverRequiredENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (HandoverRequiredIETable) infoHandoverType() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-HandoverType"}}}
}

// HandoverType returns the typed binding for the HandoverType row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) HandoverType() HandoverRequiredHandoverTypeIEBinding {
	return HandoverRequiredHandoverTypeIEBinding{info: t.infoHandoverType(), codec: func() s00.HandoverTypeValueCodec {
		sealed := s00.HandoverTypeValueCodec{}
		*s00.BridgeHandoverTypeValueCodecFieldPath(&sealed) = "HandoverType"
		*s00.BridgeHandoverTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.HandoverType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("HandoverType")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s00.HandoverType
				return empty, runtime.WrapDecodePath(err, "HandoverType")
			}
			value, ok := decoded.AsHandoverType()
			if !ok {
				var empty s00.HandoverType
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-HandoverType: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeHandoverTypeValueCodecFieldEncode(&sealed) = func(value s00.HandoverType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(1), rowHandoverType: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.HandoverType) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(1), rowHandoverType: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.HandoverType, bool) { return value.AsHandoverType() }}
}
func (HandoverRequiredIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) Cause() HandoverRequiredCauseIEBinding {
	return HandoverRequiredCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (HandoverRequiredIETable) infoTargetID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(4), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TargetID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-TargetID"}}}
}

// TargetID returns the typed binding for the TargetID row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) TargetID() HandoverRequiredTargetIDIEBinding {
	return HandoverRequiredTargetIDIEBinding{info: t.infoTargetID(), codec: TargetIDValueCodec{path: "TargetID",
		decode: func(data []byte, options aper.DecodeState) (TargetID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TargetID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TargetID")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(4), raw)
			if err != nil {
				var empty TargetID
				return empty, runtime.WrapDecodePath(err, "TargetID")
			}
			value, ok := decoded.AsTargetID()
			if !ok {
				var empty TargetID
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-TargetID: no selected value")
			}
			return *value, nil
		},
		encode: func(value TargetID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(4), rowTargetID: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TargetID, options aper.DecodeState) (TargetID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			BridgeCaptureS1APTargetID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v TargetID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTargetID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TargetID) HandoverRequiredIEValue {
		return HandoverRequiredIEValue{id: s00.ProtocolIEID(4), rowTargetID: &value}
	}, get: func(value *HandoverRequiredIEValue) (*TargetID, bool) { return value.AsTargetID() }}
}
func (HandoverRequiredIETable) infoDirectForwardingPathAvailability() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(79), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Direct-Forwarding-Path-Availability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-Direct-Forwarding-Path-Availability"}}}
}

// DirectForwardingPathAvailability returns the typed binding for the DirectForwardingPathAvailability row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) DirectForwardingPathAvailability() HandoverRequiredDirectForwardingPathAvailabilityIEBinding {
	return HandoverRequiredDirectForwardingPathAvailabilityIEBinding{info: t.infoDirectForwardingPathAvailability(), codec: func() s00.DirectForwardingPathAvailabilityValueCodec {
		sealed := s00.DirectForwardingPathAvailabilityValueCodec{}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldPath(&sealed) = "DirectForwardingPathAvailability"
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DirectForwardingPathAvailability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DirectForwardingPathAvailability")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(79), raw)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, runtime.WrapDecodePath(err, "DirectForwardingPathAvailability")
			}
			value, ok := decoded.AsDirectForwardingPathAvailability()
			if !ok {
				var empty s00.DirectForwardingPathAvailability
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-Direct-Forwarding-Path-Availability: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&sealed) = func(value s00.DirectForwardingPathAvailability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldCapture(&sealed) = func(v s00.DirectForwardingPathAvailability, options aper.DecodeState) (s00.DirectForwardingPathAvailability, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APDirectForwardingPathAvailability(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldCompare(&sealed) = func(v s00.DirectForwardingPathAvailability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDirectForwardingPathAvailability(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DirectForwardingPathAvailability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DirectForwardingPathAvailability) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.DirectForwardingPathAvailability, bool) {
			return value.AsDirectForwardingPathAvailability()
		}}
}
func (HandoverRequiredIETable) infoSRVCCHOIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(125), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCHOIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-SRVCCHOIndication"}}}
}

// SRVCCHOIndication returns the typed binding for the SRVCCHOIndication row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) SRVCCHOIndication() HandoverRequiredSRVCCHOIndicationIEBinding {
	return HandoverRequiredSRVCCHOIndicationIEBinding{info: t.infoSRVCCHOIndication(), codec: func() s01.SRVCCHOIndicationValueCodec {
		sealed := s01.SRVCCHOIndicationValueCodec{}
		*s01.BridgeSRVCCHOIndicationValueCodecFieldPath(&sealed) = "SRVCCHOIndication"
		*s01.BridgeSRVCCHOIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCHOIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCHOIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCHOIndication")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(125), raw)
			if err != nil {
				var empty s00.SRVCCHOIndication
				return empty, runtime.WrapDecodePath(err, "SRVCCHOIndication")
			}
			value, ok := decoded.AsSRVCCHOIndication()
			if !ok {
				var empty s00.SRVCCHOIndication
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-SRVCCHOIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSRVCCHOIndicationValueCodecFieldEncode(&sealed) = func(value s00.SRVCCHOIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(125), rowSRVCCHOIndication: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSRVCCHOIndicationValueCodecFieldCapture(&sealed) = func(v s00.SRVCCHOIndication, options aper.DecodeState) (s00.SRVCCHOIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCHOIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeSRVCCHOIndicationValueCodecFieldCompare(&sealed) = func(v s00.SRVCCHOIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APSRVCCHOIndication(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeSRVCCHOIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCHOIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCHOIndication) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(125), rowSRVCCHOIndication: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.SRVCCHOIndication, bool) {
			return value.AsSRVCCHOIndication()
		}}
}
func (HandoverRequiredIETable) infoSourceToTargetTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(104), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Source-ToTarget-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-Source-ToTarget-TransparentContainer"}}}
}

// SourceToTargetTransparentContainer returns the typed binding for the SourceToTargetTransparentContainer row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) SourceToTargetTransparentContainer() HandoverRequiredSourceToTargetTransparentContainerIEBinding {
	return HandoverRequiredSourceToTargetTransparentContainerIEBinding{info: t.infoSourceToTargetTransparentContainer(), codec: func() s01.SourceToTargetTransparentContainerValueCodec {
		sealed := s01.SourceToTargetTransparentContainerValueCodec{}
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldPath(&sealed) = "SourceToTargetTransparentContainer"
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SourceToTargetTransparentContainer")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(104), raw)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, runtime.WrapDecodePath(err, "SourceToTargetTransparentContainer")
			}
			value, ok := decoded.AsSourceToTargetTransparentContainer()
			if !ok {
				var empty s00.SourceToTargetTransparentContainer
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-Source-ToTarget-TransparentContainer: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceToTargetTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(104), rowSourceToTargetTransparentContainer: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.SourceToTargetTransparentContainer) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(104), rowSourceToTargetTransparentContainer: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.SourceToTargetTransparentContainer, bool) {
			return value.AsSourceToTargetTransparentContainer()
		}}
}
func (HandoverRequiredIETable) infoSourceToTargetTransparentContainerSecondary() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(138), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Source-ToTarget-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-Source-ToTarget-TransparentContainer-Secondary"}}}
}

// SourceToTargetTransparentContainerSecondary returns the typed binding for the SourceToTargetTransparentContainerSecondary row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) SourceToTargetTransparentContainerSecondary() HandoverRequiredSourceToTargetTransparentContainerIEBinding {
	return HandoverRequiredSourceToTargetTransparentContainerIEBinding{info: t.infoSourceToTargetTransparentContainerSecondary(), codec: func() s01.SourceToTargetTransparentContainerValueCodec {
		sealed := s01.SourceToTargetTransparentContainerValueCodec{}
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldPath(&sealed) = "SourceToTargetTransparentContainer"
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SourceToTargetTransparentContainer")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(138), raw)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, runtime.WrapDecodePath(err, "SourceToTargetTransparentContainer")
			}
			value, ok := decoded.AsSourceToTargetTransparentContainerSecondary()
			if !ok {
				var empty s00.SourceToTargetTransparentContainer
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-Source-ToTarget-TransparentContainer-Secondary: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceToTargetTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(138), rowSourceToTargetTransparentContainerSecondary: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s00.SourceToTargetTransparentContainer) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(138), rowSourceToTargetTransparentContainerSecondary: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.SourceToTargetTransparentContainer, bool) {
			return value.AsSourceToTargetTransparentContainerSecondary()
		}}
}
func (HandoverRequiredIETable) infoMSClassmark2() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(132), Criticality: s00.CriticalityReject, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MSClassmark2"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-MSClassmark2"}}}
}

// MSClassmark2 returns the typed binding for the MSClassmark2 row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) MSClassmark2() HandoverRequiredMSClassmark2IEBinding {
	return HandoverRequiredMSClassmark2IEBinding{info: t.infoMSClassmark2(), codec: func() s01.MSClassmark2ValueCodec {
		sealed := s01.MSClassmark2ValueCodec{}
		*s01.BridgeMSClassmark2ValueCodecFieldPath(&sealed) = "MSClassmark2"
		*s01.BridgeMSClassmark2ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MSClassmark2, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MSClassmark2
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MSClassmark2")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(132), raw)
			if err != nil {
				var empty s00.MSClassmark2
				return empty, runtime.WrapDecodePath(err, "MSClassmark2")
			}
			value, ok := decoded.AsMSClassmark2()
			if !ok {
				var empty s00.MSClassmark2
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-MSClassmark2: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMSClassmark2ValueCodecFieldEncode(&sealed) = func(value s00.MSClassmark2, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(132), rowMSClassmark2: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMSClassmark2ValueCodecFieldCapture(&sealed) = func(v s00.MSClassmark2, options aper.DecodeState) (s00.MSClassmark2, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMSClassmark2(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMSClassmark2ValueCodecFieldCompare(&sealed) = func(v s00.MSClassmark2, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMSClassmark2(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeMSClassmark2ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MSClassmark2"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MSClassmark2) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(132), rowMSClassmark2: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.MSClassmark2, bool) { return value.AsMSClassmark2() }}
}
func (HandoverRequiredIETable) infoMSClassmark3() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(133), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MSClassmark3"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-MSClassmark3"}}}
}

// MSClassmark3 returns the typed binding for the MSClassmark3 row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) MSClassmark3() HandoverRequiredMSClassmark3IEBinding {
	return HandoverRequiredMSClassmark3IEBinding{info: t.infoMSClassmark3(), codec: func() s01.MSClassmark3ValueCodec {
		sealed := s01.MSClassmark3ValueCodec{}
		*s01.BridgeMSClassmark3ValueCodecFieldPath(&sealed) = "MSClassmark3"
		*s01.BridgeMSClassmark3ValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MSClassmark3, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MSClassmark3
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MSClassmark3")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(133), raw)
			if err != nil {
				var empty s00.MSClassmark3
				return empty, runtime.WrapDecodePath(err, "MSClassmark3")
			}
			value, ok := decoded.AsMSClassmark3()
			if !ok {
				var empty s00.MSClassmark3
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-MSClassmark3: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMSClassmark3ValueCodecFieldEncode(&sealed) = func(value s00.MSClassmark3, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(133), rowMSClassmark3: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMSClassmark3ValueCodecFieldCapture(&sealed) = func(v s00.MSClassmark3, options aper.DecodeState) (s00.MSClassmark3, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMSClassmark3(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMSClassmark3ValueCodecFieldCompare(&sealed) = func(v s00.MSClassmark3, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMSClassmark3(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeMSClassmark3ValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MSClassmark3"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MSClassmark3) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(133), rowMSClassmark3: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.MSClassmark3, bool) { return value.AsMSClassmark3() }}
}
func (HandoverRequiredIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-CSG-Id"}}}
}

// CSGId returns the typed binding for the CSGId row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) CSGId() HandoverRequiredCSGIdIEBinding {
	return HandoverRequiredCSGIdIEBinding{info: t.infoCSGId(), codec: func() s00.CSGIdValueCodec {
		sealed := s00.CSGIdValueCodec{}
		*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
		*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGId
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGId")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(127), raw)
			if err != nil {
				var empty s00.CSGId
				return empty, runtime.WrapDecodePath(err, "CSGId")
			}
			value, ok := decoded.AsCSGId()
			if !ok {
				var empty s00.CSGId
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-CSG-Id: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CSGId) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(127), rowCSGId: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }}
}
func (HandoverRequiredIETable) infoCellAccessMode() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(145), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CellAccessMode"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-CellAccessMode"}}}
}

// CellAccessMode returns the typed binding for the CellAccessMode row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) CellAccessMode() HandoverRequiredCellAccessModeIEBinding {
	return HandoverRequiredCellAccessModeIEBinding{info: t.infoCellAccessMode(), codec: func() s00.CellAccessModeValueCodec {
		sealed := s00.CellAccessModeValueCodec{}
		*s00.BridgeCellAccessModeValueCodecFieldPath(&sealed) = "CellAccessMode"
		*s00.BridgeCellAccessModeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellAccessMode, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CellAccessMode")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(145), raw)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, runtime.WrapDecodePath(err, "CellAccessMode")
			}
			value, ok := decoded.AsCellAccessMode()
			if !ok {
				var empty s00.CellAccessMode
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-CellAccessMode: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellAccessModeValueCodecFieldEncode(&sealed) = func(value s00.CellAccessMode, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CellAccessMode) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(145), rowCellAccessMode: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.CellAccessMode, bool) { return value.AsCellAccessMode() }}
}
func (HandoverRequiredIETable) infoPSServiceNotAvailable() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequiredIEs().ID(), ID: s00.ProtocolIEID(150), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PS-ServiceNotAvailable"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequiredIEs", Row: "id-PS-ServiceNotAvailable"}}}
}

// PSServiceNotAvailable returns the typed binding for the PSServiceNotAvailable row of HandoverRequiredIETable.
func (t HandoverRequiredIETable) PSServiceNotAvailable() HandoverRequiredPSServiceNotAvailableIEBinding {
	return HandoverRequiredPSServiceNotAvailableIEBinding{info: t.infoPSServiceNotAvailable(), codec: func() s01.PSServiceNotAvailableValueCodec {
		sealed := s01.PSServiceNotAvailableValueCodec{}
		*s01.BridgePSServiceNotAvailableValueCodecFieldPath(&sealed) = "PSServiceNotAvailable"
		*s01.BridgePSServiceNotAvailableValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PSServiceNotAvailable, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PSServiceNotAvailable
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PSServiceNotAvailable")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(150), raw)
			if err != nil {
				var empty s00.PSServiceNotAvailable
				return empty, runtime.WrapDecodePath(err, "PSServiceNotAvailable")
			}
			value, ok := decoded.AsPSServiceNotAvailable()
			if !ok {
				var empty s00.PSServiceNotAvailable
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-PS-ServiceNotAvailable: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePSServiceNotAvailableValueCodecFieldEncode(&sealed) = func(value s00.PSServiceNotAvailable, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(150), rowPSServiceNotAvailable: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePSServiceNotAvailableValueCodecFieldCapture(&sealed) = func(v s00.PSServiceNotAvailable, options aper.DecodeState) (s00.PSServiceNotAvailable, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPSServiceNotAvailable(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgePSServiceNotAvailableValueCodecFieldCompare(&sealed) = func(v s00.PSServiceNotAvailable, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPSServiceNotAvailable(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePSServiceNotAvailableValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PSServiceNotAvailable"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PSServiceNotAvailable) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(150), rowPSServiceNotAvailable: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s00.PSServiceNotAvailable, bool) {
			return value.AsPSServiceNotAvailable()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverRequiredIETable.
func (t HandoverRequiredIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (HandoverRequiredIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(4):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-TargetID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(79):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-Direct-Forwarding-Path-Availability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(125):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCHOIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(104):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-Source-ToTarget-TransparentContainer requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(138):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-Source-ToTarget-TransparentContainer-Secondary requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(132):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-MSClassmark2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(133):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-MSClassmark3 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(145):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-CellAccessMode requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(150):
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("known IE id-PS-ServiceNotAvailable requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverRequiredIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverRequiredIEField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverRequiredIEField{Id: id, Criticality: criticality, Value: HandoverRequiredIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEDirectInformationTransferIETable struct{}

func MMEDirectInformationTransferIEs() MMEDirectInformationTransferIETable {
	return MMEDirectInformationTransferIETable{}
}

// ID returns the ASN.1 object-set identity of MMEDirectInformationTransferIETable.
func (MMEDirectInformationTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEDirectInformationTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEDirectInformationTransferIETable.
func (MMEDirectInformationTransferIETable) Table() s00.MMEDirectInformationTransferIEValueIETable {
	return func() s00.MMEDirectInformationTransferIEValueIETable {
		sealed := s00.MMEDirectInformationTransferIEValueIETable{}
		*s00.BridgeMMEDirectInformationTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEDirectInformationTransferIETable) infoInterSystemInformationTransferTypeMDT() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEDirectInformationTransferIEs().ID(), ID: s00.ProtocolIEID(122), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "Inter-SystemInformationTransferType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEDirectInformationTransferIEs", Row: "id-Inter-SystemInformationTransferTypeMDT"}}}
}

// InterSystemInformationTransferTypeMDT returns the typed binding for the InterSystemInformationTransferTypeMDT row of MMEDirectInformationTransferIETable.
func (t MMEDirectInformationTransferIETable) InterSystemInformationTransferTypeMDT() MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding {
	return MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding{info: t.infoInterSystemInformationTransferTypeMDT(), codec: InterSystemInformationTransferTypeValueCodec{path: "InterSystemInformationTransferType",
		decode: func(data []byte, options aper.DecodeState) (InterSystemInformationTransferType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("InterSystemInformationTransferType")
			var zero MMEDirectInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(122), raw)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, runtime.WrapDecodePath(err, "InterSystemInformationTransferType")
			}
			value, ok := decoded.AsInterSystemInformationTransferTypeMDT()
			if !ok {
				var empty InterSystemInformationTransferType
				return empty, fmt.Errorf("binding MMEDirectInformationTransferIEs.id-Inter-SystemInformationTransferTypeMDT: no selected value")
			}
			return *value, nil
		},
		encode: func(value InterSystemInformationTransferType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEDirectInformationTransferIEValue{id: s00.ProtocolIEID(122), rowInterSystemInformationTransferTypeMDT: &value}).encodeFresh(fresh, budget)
		}, capture: func(v InterSystemInformationTransferType, options aper.DecodeState) (InterSystemInformationTransferType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APInterSystemInformationTransferType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v InterSystemInformationTransferType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APInterSystemInformationTransferType(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterSystemInformationTransferType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value InterSystemInformationTransferType) MMEDirectInformationTransferIEValue {
		return MMEDirectInformationTransferIEValue{id: s00.ProtocolIEID(122), rowInterSystemInformationTransferTypeMDT: &value}
	}, get: func(value *MMEDirectInformationTransferIEValue) (*InterSystemInformationTransferType, bool) {
		return value.AsInterSystemInformationTransferTypeMDT()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEDirectInformationTransferIETable.
func (t MMEDirectInformationTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEDirectInformationTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(122):
		return MMEDirectInformationTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-Inter-SystemInformationTransferTypeMDT requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEDirectInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEDirectInformationTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEDirectInformationTransferIEField{Id: id, Criticality: criticality, Value: MMEDirectInformationTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type TAIItemIETable struct{}

func TAIItemIEs() TAIItemIETable { return TAIItemIETable{} }

// ID returns the ASN.1 object-set identity of TAIItemIETable.
func (TAIItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIItemIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TAIItemIETable.
func (TAIItemIETable) Table() s00.TAIItemIEValueIETable {
	return func() s00.TAIItemIEValueIETable {
		sealed := s00.TAIItemIEValueIETable{}
		*s00.BridgeTAIItemIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TAIItemIETable) infoTAIItem() s00.FieldInfo {
	return s00.FieldInfo{Table: TAIItemIEs().ID(), ID: s00.ProtocolIEID(47), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIItemIEs", Row: "id-TAIItem"}}}
}

// TAIItem returns the typed binding for the TAIItem row of TAIItemIETable.
func (t TAIItemIETable) TAIItem() TAIItemTAIItemIEBinding {
	return TAIItemTAIItemIEBinding{info: t.infoTAIItem(), codec: TAIItemValueCodec{path: "TAIItem",
		decode: func(data []byte, options aper.DecodeState) (TAIItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TAIItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAIItem")
			var zero TAIItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(47), raw)
			if err != nil {
				var empty TAIItem
				return empty, runtime.WrapDecodePath(err, "TAIItem")
			}
			value, ok := decoded.AsTAIItem()
			if !ok {
				var empty TAIItem
				return empty, fmt.Errorf("binding TAIItemIEs.id-TAIItem: no selected value")
			}
			return *value, nil
		},
		encode: func(value TAIItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TAIItemIEValue{id: s00.ProtocolIEID(47), rowTAIItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TAIItem, options aper.DecodeState) (TAIItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			BridgeCaptureS1APTAIItem(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v TAIItem, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTAIItem(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIItem"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TAIItem) TAIItemIEValue {
		return TAIItemIEValue{id: s00.ProtocolIEID(47), rowTAIItem: &value}
	}, get: func(value *TAIItemIEValue) (*TAIItem, bool) { return value.AsTAIItem() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TAIItemIETable.
func (t TAIItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (TAIItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TAIItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(47):
		return TAIItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAIItem requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TAIItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TAIItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return TAIItemIEField{Id: id, Criticality: criticality, Value: TAIItemIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// InterSystemInformationTransferTypeCodec binds the complete APER value type.
func InterSystemInformationTransferTypeCodec() InterSystemInformationTransferTypeValueCodec {
	return ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Codec()
}

// MSClassmark2Codec binds the complete APER value type.
func MSClassmark2Codec() s01.MSClassmark2ValueCodec {
	return HandoverRequiredIEs().MSClassmark2().Codec()
}

// MSClassmark3Codec binds the complete APER value type.
func MSClassmark3Codec() s01.MSClassmark3ValueCodec {
	return HandoverRequiredIEs().MSClassmark3().Codec()
}

// PSServiceNotAvailableCodec binds the complete APER value type.
func PSServiceNotAvailableCodec() s01.PSServiceNotAvailableValueCodec {
	return HandoverRequiredIEs().PSServiceNotAvailable().Codec()
}

// RIMRoutingAddressCodec binds the complete source value type.
func RIMRoutingAddressCodec() RIMRoutingAddressValueCodec {
	return RIMRoutingAddressValueCodec{path: "RIMRoutingAddress", decode: func(data []byte, options aper.DecodeState) (RIMRoutingAddress, error) {
		var value RIMRoutingAddress
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RIMRoutingAddress{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RIMRoutingAddress, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RIMRoutingAddress, options aper.DecodeState) (RIMRoutingAddress, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRIMRoutingAddress(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v RIMRoutingAddress, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRIMRoutingAddress(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RIMRoutingAddress"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// RIMTransferCodec binds the complete source value type.
func RIMTransferCodec() RIMTransferValueCodec {
	return RIMTransferValueCodec{path: "RIMTransfer", decode: func(data []byte, options aper.DecodeState) (RIMTransfer, error) {
		var value RIMTransfer
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RIMTransfer{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RIMTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RIMTransfer, options aper.DecodeState) (RIMTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRIMTransfer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v RIMTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRIMTransfer(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RIMTransfer"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// RecommendedENBsForPagingCodec binds the complete source value type.
func RecommendedENBsForPagingCodec() RecommendedENBsForPagingValueCodec {
	return RecommendedENBsForPagingValueCodec{path: "RecommendedENBsForPaging", decode: func(data []byte, options aper.DecodeState) (s33.RecommendedENBsForPaging, error) {
		var value s33.RecommendedENBsForPaging
		if err := s33.BridgeRecommendedENBsForPagingMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s33.RecommendedENBsForPaging{}, err
		}
		*s33.BridgeRecommendedENBsForPagingFieldReceived(&value) = true
		*s33.BridgeRecommendedENBsForPagingFieldReceivedAbsolute(&value) = true
		*s33.BridgeRecommendedENBsForPagingFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s33.RecommendedENBsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s33.BridgeRecommendedENBsForPagingMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s33.RecommendedENBsForPaging, options aper.DecodeState) (s33.RecommendedENBsForPaging, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s33.BridgeCaptureS1APRecommendedENBsForPaging(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s33.RecommendedENBsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s33.BridgeCompareS1APRecommendedENBsForPaging(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RecommendedENBsForPaging"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SRVCCHOIndicationCodec binds the complete APER value type.
func SRVCCHOIndicationCodec() s01.SRVCCHOIndicationValueCodec {
	return HandoverRequiredIEs().SRVCCHOIndication().Codec()
}

// TAIItemCodec binds the complete APER value type.
func TAIItemCodec() TAIItemValueCodec { return TAIItemIEs().TAIItem().Codec() }

// TargetIDCodec binds the complete APER value type.
func TargetIDCodec() TargetIDValueCodec { return HandoverRequiredIEs().TargetID().Codec() }

// TargetNgRanNodeIDCodec binds the complete source value type.
func TargetNgRanNodeIDCodec() TargetNgRanNodeIDValueCodec {
	return TargetNgRanNodeIDValueCodec{path: "TargetNgRanNodeID", decode: func(data []byte, options aper.DecodeState) (TargetNgRanNodeID, error) {
		var value TargetNgRanNodeID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TargetNgRanNodeID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TargetNgRanNodeID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TargetNgRanNodeID, options aper.DecodeState) (TargetNgRanNodeID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTargetNgRanNodeID(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v TargetNgRanNodeID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTargetNgRanNodeID(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetNgRanNodeID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TargetRNCIDCodec binds the complete source value type.
func TargetRNCIDCodec() TargetRNCIDValueCodec {
	return TargetRNCIDValueCodec{path: "TargetRNCID", decode: func(data []byte, options aper.DecodeState) (TargetRNCID, error) {
		var value TargetRNCID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TargetRNCID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TargetRNCID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TargetRNCID, options aper.DecodeState) (TargetRNCID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTargetRNCID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TargetRNCID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTargetRNCID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargetRNCID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeENBDirectInformationTransferAPERValueFieldContext(v *ENBDirectInformationTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferAPERValueFieldReceived(v *ENBDirectInformationTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferAPERValueFieldReplay(v *ENBDirectInformationTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferFieldExtCount(v *ENBDirectInformationTransfer) *int64 {
	return &v.extCount
}
func BridgeENBDirectInformationTransferFieldExtData(v *ENBDirectInformationTransfer) *[][]byte {
	return &v.extData
}
func BridgeENBDirectInformationTransferFieldExtOrigin(v *ENBDirectInformationTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBDirectInformationTransferFieldExtPresent(v *ENBDirectInformationTransfer) *[]bool {
	return &v.extPresent
}
func BridgeENBDirectInformationTransferFieldExtWire(v *ENBDirectInformationTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBDirectInformationTransferFieldPerExtPadding(v *ENBDirectInformationTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBDirectInformationTransferFieldPerPadding(v *ENBDirectInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBDirectInformationTransferFieldProtocolIEsIndef(v *ENBDirectInformationTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBDirectInformationTransferFieldReceived(v *ENBDirectInformationTransfer) *bool {
	return &v.received
}
func BridgeENBDirectInformationTransferFieldReceivedAbsolute(v *ENBDirectInformationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBDirectInformationTransferFieldReceivedBytes(v *ENBDirectInformationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBDirectInformationTransferFieldReceivedLocation(v *ENBDirectInformationTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBDirectInformationTransferFieldReplay(v *ENBDirectInformationTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferFieldStream(v *ENBDirectInformationTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeENBDirectInformationTransferFieldWithoutReplay(v *ENBDirectInformationTransfer) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEContainerAPERValueFieldContext(v *ENBDirectInformationTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEContainerAPERValueFieldReceived(v *ENBDirectInformationTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEContainerAPERValueFieldReplay(v *ENBDirectInformationTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEContainerAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldCapture(v *ENBDirectInformationTransferIEContainerValueCodec) *func(ENBDirectInformationTransferIEContainer, aper.DecodeState) (ENBDirectInformationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldCompare(v *ENBDirectInformationTransferIEContainerValueCodec) *func(ENBDirectInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldContext(v *ENBDirectInformationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(v *ENBDirectInformationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldEncode(v *ENBDirectInformationTransferIEContainerValueCodec) *func(ENBDirectInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferIEContainerValueCodecFieldPath(v *ENBDirectInformationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferIEContainerValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferIEContainerValueCodec, a0 ENBDirectInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferIEContainerValueCodecMethodEncodeChanged(v ENBDirectInformationTransferIEContainerValueCodec, a0 ENBDirectInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBDirectInformationTransferIEFieldAPERValueFieldContext(v *ENBDirectInformationTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEFieldAPERValueFieldReceived(v *ENBDirectInformationTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEFieldAPERValueFieldReplay(v *ENBDirectInformationTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEFieldAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEFieldFieldReceived(v *ENBDirectInformationTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBDirectInformationTransferIEFieldFieldReplay(v *ENBDirectInformationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEFieldFieldStream(v *ENBDirectInformationTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBDirectInformationTransferIEFieldFieldWithoutReplay(v *ENBDirectInformationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEFieldMethodMarshalAPERTo(v *ENBDirectInformationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(v *ENBDirectInformationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldCapture(v *ENBDirectInformationTransferIEFieldValueCodec) *func(ENBDirectInformationTransferIEField, aper.DecodeState) (ENBDirectInformationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldCompare(v *ENBDirectInformationTransferIEFieldValueCodec) *func(ENBDirectInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldContext(v *ENBDirectInformationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldDecode(v *ENBDirectInformationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEField, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldEncode(v *ENBDirectInformationTransferIEFieldValueCodec) *func(ENBDirectInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferIEFieldValueCodecFieldPath(v *ENBDirectInformationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferIEFieldValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferIEFieldValueCodec, a0 ENBDirectInformationTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferIEFieldValueCodecMethodEncodeChanged(v ENBDirectInformationTransferIEFieldValueCodec, a0 ENBDirectInformationTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBDirectInformationTransferIETableMethodInfoInterSystemInformationTransferTypeEDT(v ENBDirectInformationTransferIETable) s00.FieldInfo {
	return v.infoInterSystemInformationTransferTypeEDT()
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListAPERValueFieldContext(v *ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListAPERValueFieldReceived(v *ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListAPERValueFieldReplay(v *ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueERABIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBDirectInformationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferIEValueERABIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBDirectInformationTransferIEValueERABIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBDirectInformationTransferIEValueFieldId(v *ENBDirectInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBDirectInformationTransferIEValueFieldIsOpaque(v *ENBDirectInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBDirectInformationTransferIEValueFieldOpaque(v *ENBDirectInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBDirectInformationTransferIEValueFieldReceived(v *ENBDirectInformationTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEValueFieldReplay(v *ENBDirectInformationTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeEDT(v *ENBDirectInformationTransferIEValue) **InterSystemInformationTransferType {
	return &v.rowInterSystemInformationTransferTypeEDT
}
func BridgeENBDirectInformationTransferIEValueMethodCaptureSemantics(v ENBDirectInformationTransferIEValue, a0 aper.SemanticCapture) ENBDirectInformationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBDirectInformationTransferIEValueMethodCompareSemantics(v ENBDirectInformationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBDirectInformationTransferIEValueMethodDecode(v ENBDirectInformationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBDirectInformationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBDirectInformationTransferIEValueMethodEncode(v ENBDirectInformationTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBDirectInformationTransferIEValueMethodEncodeFresh(v ENBDirectInformationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBDirectInformationTransferIEValueMethodMatchesID(v ENBDirectInformationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBDirectInformationTransferIEValueMethodReason(v ENBDirectInformationTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBDirectInformationTransferIEValueMethodRule(v ENBDirectInformationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBDirectInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec, a0 ENBDirectInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldCodec(v *ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *InterSystemInformationTransferTypeValueCodec {
	return &v.codec
}
func BridgeENBDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldGet(v *ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *func(*ENBDirectInformationTransferIEValue) (*InterSystemInformationTransferType, bool) {
	return &v.get
}
func BridgeENBDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldInfo(v *ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldInject(v *ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *func(InterSystemInformationTransferType) ENBDirectInformationTransferIEValue {
	return &v.inject
}
func BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v *ENBDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERBudgetValue(v *ENBDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERChanged(v *ENBDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERChangedValue(v *ENBDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERLegacy(v *ENBDirectInformationTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBDirectInformationTransferMethodMarshalAPERNewValue(v *ENBDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERPlanned(v *ENBDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBDirectInformationTransferMethodMarshalAPERTo(v *ENBDirectInformationTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBDirectInformationTransferMethodUnmarshalAPERFrom(v *ENBDirectInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBDirectInformationTransferMethodUnmarshalAPERLegacy(v *ENBDirectInformationTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBDirectInformationTransferMethodUnmarshalAPERWithOptions(v *ENBDirectInformationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBDirectInformationTransferValueCodecFieldCapture(v *ENBDirectInformationTransferValueCodec) *func(ENBDirectInformationTransfer, aper.DecodeState) (ENBDirectInformationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBDirectInformationTransferValueCodecFieldCompare(v *ENBDirectInformationTransferValueCodec) *func(ENBDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBDirectInformationTransferValueCodecFieldContext(v *ENBDirectInformationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBDirectInformationTransferValueCodecFieldDecode(v *ENBDirectInformationTransferValueCodec) *func([]byte, aper.DecodeState) (ENBDirectInformationTransfer, error) {
	return &v.decode
}
func BridgeENBDirectInformationTransferValueCodecFieldEncode(v *ENBDirectInformationTransferValueCodec) *func(ENBDirectInformationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBDirectInformationTransferValueCodecFieldPath(v *ENBDirectInformationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBDirectInformationTransferValueCodecMethodEncodeBudgetValue(v ENBDirectInformationTransferValueCodec, a0 ENBDirectInformationTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBDirectInformationTransferValueCodecMethodEncodeChanged(v ENBDirectInformationTransferValueCodec, a0 ENBDirectInformationTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredCSGIdIEBindingFieldCodec(v *HandoverRequiredCSGIdIEBinding) *s00.CSGIdValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredCSGIdIEBindingFieldGet(v *HandoverRequiredCSGIdIEBinding) *func(*HandoverRequiredIEValue) (*s00.CSGId, bool) {
	return &v.get
}
func BridgeHandoverRequiredCSGIdIEBindingFieldInfo(v *HandoverRequiredCSGIdIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredCSGIdIEBindingFieldInject(v *HandoverRequiredCSGIdIEBinding) *func(s00.CSGId) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredCauseIEBindingFieldCodec(v *HandoverRequiredCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredCauseIEBindingFieldGet(v *HandoverRequiredCauseIEBinding) *func(*HandoverRequiredIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeHandoverRequiredCauseIEBindingFieldInfo(v *HandoverRequiredCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredCauseIEBindingFieldInject(v *HandoverRequiredCauseIEBinding) *func(s14.Cause) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredCellAccessModeIEBindingFieldCodec(v *HandoverRequiredCellAccessModeIEBinding) *s00.CellAccessModeValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredCellAccessModeIEBindingFieldGet(v *HandoverRequiredCellAccessModeIEBinding) *func(*HandoverRequiredIEValue) (*s00.CellAccessMode, bool) {
	return &v.get
}
func BridgeHandoverRequiredCellAccessModeIEBindingFieldInfo(v *HandoverRequiredCellAccessModeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredCellAccessModeIEBindingFieldInject(v *HandoverRequiredCellAccessModeIEBinding) *func(s00.CellAccessMode) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredDirectForwardingPathAvailabilityIEBindingFieldCodec(v *HandoverRequiredDirectForwardingPathAvailabilityIEBinding) *s00.DirectForwardingPathAvailabilityValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredDirectForwardingPathAvailabilityIEBindingFieldGet(v *HandoverRequiredDirectForwardingPathAvailabilityIEBinding) *func(*HandoverRequiredIEValue) (*s00.DirectForwardingPathAvailability, bool) {
	return &v.get
}
func BridgeHandoverRequiredDirectForwardingPathAvailabilityIEBindingFieldInfo(v *HandoverRequiredDirectForwardingPathAvailabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredDirectForwardingPathAvailabilityIEBindingFieldInject(v *HandoverRequiredDirectForwardingPathAvailabilityIEBinding) *func(s00.DirectForwardingPathAvailability) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredENBUES1APIDIEBindingFieldCodec(v *HandoverRequiredENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredENBUES1APIDIEBindingFieldGet(v *HandoverRequiredENBUES1APIDIEBinding) *func(*HandoverRequiredIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeHandoverRequiredENBUES1APIDIEBindingFieldInfo(v *HandoverRequiredENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredENBUES1APIDIEBindingFieldInject(v *HandoverRequiredENBUES1APIDIEBinding) *func(s00.ENBUES1APID) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredHandoverTypeIEBindingFieldCodec(v *HandoverRequiredHandoverTypeIEBinding) *s00.HandoverTypeValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredHandoverTypeIEBindingFieldGet(v *HandoverRequiredHandoverTypeIEBinding) *func(*HandoverRequiredIEValue) (*s00.HandoverType, bool) {
	return &v.get
}
func BridgeHandoverRequiredHandoverTypeIEBindingFieldInfo(v *HandoverRequiredHandoverTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredHandoverTypeIEBindingFieldInject(v *HandoverRequiredHandoverTypeIEBinding) *func(s00.HandoverType) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredIEContainerAPERValueFieldContext(v *HandoverRequiredIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEContainerAPERValueFieldReceived(v *HandoverRequiredIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEContainerAPERValueFieldReplay(v *HandoverRequiredIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEContainerAPERValueFieldWithoutReplay(v *HandoverRequiredIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEContainerValueCodecFieldCapture(v *HandoverRequiredIEContainerValueCodec) *func(HandoverRequiredIEContainer, aper.DecodeState) (HandoverRequiredIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredIEContainerValueCodecFieldCompare(v *HandoverRequiredIEContainerValueCodec) *func(HandoverRequiredIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredIEContainerValueCodecFieldContext(v *HandoverRequiredIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEContainerValueCodecFieldDecode(v *HandoverRequiredIEContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverRequiredIEContainer, error) {
	return &v.decode
}
func BridgeHandoverRequiredIEContainerValueCodecFieldEncode(v *HandoverRequiredIEContainerValueCodec) *func(HandoverRequiredIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredIEContainerValueCodecFieldPath(v *HandoverRequiredIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequiredIEContainerValueCodecMethodEncodeBudgetValue(v HandoverRequiredIEContainerValueCodec, a0 HandoverRequiredIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredIEContainerValueCodecMethodEncodeChanged(v HandoverRequiredIEContainerValueCodec, a0 HandoverRequiredIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredIEFieldAPERValueFieldContext(v *HandoverRequiredIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEFieldAPERValueFieldReceived(v *HandoverRequiredIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEFieldAPERValueFieldReplay(v *HandoverRequiredIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEFieldAPERValueFieldWithoutReplay(v *HandoverRequiredIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEFieldFieldReceived(v *HandoverRequiredIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverRequiredIEFieldFieldReplay(v *HandoverRequiredIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEFieldFieldStream(v *HandoverRequiredIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRequiredIEFieldFieldWithoutReplay(v *HandoverRequiredIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(v *HandoverRequiredIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(v *HandoverRequiredIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequiredIEFieldValueCodecFieldCapture(v *HandoverRequiredIEFieldValueCodec) *func(HandoverRequiredIEField, aper.DecodeState) (HandoverRequiredIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredIEFieldValueCodecFieldCompare(v *HandoverRequiredIEFieldValueCodec) *func(HandoverRequiredIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredIEFieldValueCodecFieldContext(v *HandoverRequiredIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEFieldValueCodecFieldDecode(v *HandoverRequiredIEFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverRequiredIEField, error) {
	return &v.decode
}
func BridgeHandoverRequiredIEFieldValueCodecFieldEncode(v *HandoverRequiredIEFieldValueCodec) *func(HandoverRequiredIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredIEFieldValueCodecFieldPath(v *HandoverRequiredIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequiredIEFieldValueCodecMethodEncodeBudgetValue(v HandoverRequiredIEFieldValueCodec, a0 HandoverRequiredIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredIEFieldValueCodecMethodEncodeChanged(v HandoverRequiredIEFieldValueCodec, a0 HandoverRequiredIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredIETableMethodInfoCSGId(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoCSGId()
}
func BridgeHandoverRequiredIETableMethodInfoCause(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeHandoverRequiredIETableMethodInfoCellAccessMode(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoCellAccessMode()
}
func BridgeHandoverRequiredIETableMethodInfoDirectForwardingPathAvailability(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoDirectForwardingPathAvailability()
}
func BridgeHandoverRequiredIETableMethodInfoENBUES1APID(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeHandoverRequiredIETableMethodInfoHandoverType(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoHandoverType()
}
func BridgeHandoverRequiredIETableMethodInfoMMEUES1APID(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverRequiredIETableMethodInfoMSClassmark2(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoMSClassmark2()
}
func BridgeHandoverRequiredIETableMethodInfoMSClassmark3(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoMSClassmark3()
}
func BridgeHandoverRequiredIETableMethodInfoPSServiceNotAvailable(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoPSServiceNotAvailable()
}
func BridgeHandoverRequiredIETableMethodInfoSRVCCHOIndication(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoSRVCCHOIndication()
}
func BridgeHandoverRequiredIETableMethodInfoSourceToTargetTransparentContainer(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoSourceToTargetTransparentContainer()
}
func BridgeHandoverRequiredIETableMethodInfoSourceToTargetTransparentContainerSecondary(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoSourceToTargetTransparentContainerSecondary()
}
func BridgeHandoverRequiredIETableMethodInfoTargetID(v HandoverRequiredIETable) s00.FieldInfo {
	return v.infoTargetID()
}
func BridgeHandoverRequiredIEValueERABIEContainerListAPERValueFieldContext(v *HandoverRequiredIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueERABIEContainerListAPERValueFieldReceived(v *HandoverRequiredIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEValueERABIEContainerListAPERValueFieldReplay(v *HandoverRequiredIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequiredIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldCapture(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *func(HandoverRequiredIEValueERABIEContainerList, aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldCompare(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *func(HandoverRequiredIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldContext(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldDecode(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldEncode(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *func(HandoverRequiredIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldPath(v *HandoverRequiredIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequiredIEValueERABIEContainerListValueCodec, a0 HandoverRequiredIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredIEValueERABIEContainerListValueCodecMethodEncodeChanged(v HandoverRequiredIEValueERABIEContainerListValueCodec, a0 HandoverRequiredIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredIEValueFieldId(v *HandoverRequiredIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverRequiredIEValueFieldIsOpaque(v *HandoverRequiredIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverRequiredIEValueFieldOpaque(v *HandoverRequiredIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverRequiredIEValueFieldReceived(v *HandoverRequiredIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEValueFieldReplay(v *HandoverRequiredIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEValueFieldRowCSGId(v *HandoverRequiredIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgeHandoverRequiredIEValueFieldRowCause(v *HandoverRequiredIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeHandoverRequiredIEValueFieldRowCellAccessMode(v *HandoverRequiredIEValue) **s00.CellAccessMode {
	return &v.rowCellAccessMode
}
func BridgeHandoverRequiredIEValueFieldRowDirectForwardingPathAvailability(v *HandoverRequiredIEValue) **s00.DirectForwardingPathAvailability {
	return &v.rowDirectForwardingPathAvailability
}
func BridgeHandoverRequiredIEValueFieldRowENBUES1APID(v *HandoverRequiredIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeHandoverRequiredIEValueFieldRowHandoverType(v *HandoverRequiredIEValue) **s00.HandoverType {
	return &v.rowHandoverType
}
func BridgeHandoverRequiredIEValueFieldRowMMEUES1APID(v *HandoverRequiredIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeHandoverRequiredIEValueFieldRowMSClassmark2(v *HandoverRequiredIEValue) **s00.MSClassmark2 {
	return &v.rowMSClassmark2
}
func BridgeHandoverRequiredIEValueFieldRowMSClassmark3(v *HandoverRequiredIEValue) **s00.MSClassmark3 {
	return &v.rowMSClassmark3
}
func BridgeHandoverRequiredIEValueFieldRowPSServiceNotAvailable(v *HandoverRequiredIEValue) **s00.PSServiceNotAvailable {
	return &v.rowPSServiceNotAvailable
}
func BridgeHandoverRequiredIEValueFieldRowSRVCCHOIndication(v *HandoverRequiredIEValue) **s00.SRVCCHOIndication {
	return &v.rowSRVCCHOIndication
}
func BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainer(v *HandoverRequiredIEValue) **s00.SourceToTargetTransparentContainer {
	return &v.rowSourceToTargetTransparentContainer
}
func BridgeHandoverRequiredIEValueFieldRowSourceToTargetTransparentContainerSecondary(v *HandoverRequiredIEValue) **s00.SourceToTargetTransparentContainer {
	return &v.rowSourceToTargetTransparentContainerSecondary
}
func BridgeHandoverRequiredIEValueFieldRowTargetID(v *HandoverRequiredIEValue) **TargetID {
	return &v.rowTargetID
}
func BridgeHandoverRequiredIEValueMethodCaptureSemantics(v HandoverRequiredIEValue, a0 aper.SemanticCapture) HandoverRequiredIEValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverRequiredIEValueMethodCompareSemantics(v HandoverRequiredIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverRequiredIEValueMethodDecode(v HandoverRequiredIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverRequiredIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverRequiredIEValueMethodEncode(v HandoverRequiredIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverRequiredIEValueMethodEncodeFresh(v HandoverRequiredIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverRequiredIEValueMethodMatchesID(v HandoverRequiredIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverRequiredIEValueMethodReason(v HandoverRequiredIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverRequiredIEValueMethodRule(v HandoverRequiredIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolErrorIEContainerList, aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequiredIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec, a0 HandoverRequiredIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListAPERValueFieldContext(v *HandoverRequiredIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListAPERValueFieldReceived(v *HandoverRequiredIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListAPERValueFieldReplay(v *HandoverRequiredIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *HandoverRequiredIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldCapture(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolIEContainerList, aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldCompare(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldContext(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldDecode(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldEncode(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *func(HandoverRequiredIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldPath(v *HandoverRequiredIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v HandoverRequiredIEValueProtocolIEContainerListValueCodec, a0 HandoverRequiredIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v HandoverRequiredIEValueProtocolIEContainerListValueCodec, a0 HandoverRequiredIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRequiredMMEUES1APIDIEBindingFieldCodec(v *HandoverRequiredMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredMMEUES1APIDIEBindingFieldGet(v *HandoverRequiredMMEUES1APIDIEBinding) *func(*HandoverRequiredIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeHandoverRequiredMMEUES1APIDIEBindingFieldInfo(v *HandoverRequiredMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredMMEUES1APIDIEBindingFieldInject(v *HandoverRequiredMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredMSClassmark2IEBindingFieldCodec(v *HandoverRequiredMSClassmark2IEBinding) *s01.MSClassmark2ValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredMSClassmark2IEBindingFieldGet(v *HandoverRequiredMSClassmark2IEBinding) *func(*HandoverRequiredIEValue) (*s00.MSClassmark2, bool) {
	return &v.get
}
func BridgeHandoverRequiredMSClassmark2IEBindingFieldInfo(v *HandoverRequiredMSClassmark2IEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredMSClassmark2IEBindingFieldInject(v *HandoverRequiredMSClassmark2IEBinding) *func(s00.MSClassmark2) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredMSClassmark3IEBindingFieldCodec(v *HandoverRequiredMSClassmark3IEBinding) *s01.MSClassmark3ValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredMSClassmark3IEBindingFieldGet(v *HandoverRequiredMSClassmark3IEBinding) *func(*HandoverRequiredIEValue) (*s00.MSClassmark3, bool) {
	return &v.get
}
func BridgeHandoverRequiredMSClassmark3IEBindingFieldInfo(v *HandoverRequiredMSClassmark3IEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredMSClassmark3IEBindingFieldInject(v *HandoverRequiredMSClassmark3IEBinding) *func(s00.MSClassmark3) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredPSServiceNotAvailableIEBindingFieldCodec(v *HandoverRequiredPSServiceNotAvailableIEBinding) *s01.PSServiceNotAvailableValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredPSServiceNotAvailableIEBindingFieldGet(v *HandoverRequiredPSServiceNotAvailableIEBinding) *func(*HandoverRequiredIEValue) (*s00.PSServiceNotAvailable, bool) {
	return &v.get
}
func BridgeHandoverRequiredPSServiceNotAvailableIEBindingFieldInfo(v *HandoverRequiredPSServiceNotAvailableIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredPSServiceNotAvailableIEBindingFieldInject(v *HandoverRequiredPSServiceNotAvailableIEBinding) *func(s00.PSServiceNotAvailable) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredSRVCCHOIndicationIEBindingFieldCodec(v *HandoverRequiredSRVCCHOIndicationIEBinding) *s01.SRVCCHOIndicationValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredSRVCCHOIndicationIEBindingFieldGet(v *HandoverRequiredSRVCCHOIndicationIEBinding) *func(*HandoverRequiredIEValue) (*s00.SRVCCHOIndication, bool) {
	return &v.get
}
func BridgeHandoverRequiredSRVCCHOIndicationIEBindingFieldInfo(v *HandoverRequiredSRVCCHOIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredSRVCCHOIndicationIEBindingFieldInject(v *HandoverRequiredSRVCCHOIndicationIEBinding) *func(s00.SRVCCHOIndication) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredSourceToTargetTransparentContainerIEBindingFieldCodec(v *HandoverRequiredSourceToTargetTransparentContainerIEBinding) *s01.SourceToTargetTransparentContainerValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredSourceToTargetTransparentContainerIEBindingFieldGet(v *HandoverRequiredSourceToTargetTransparentContainerIEBinding) *func(*HandoverRequiredIEValue) (*s00.SourceToTargetTransparentContainer, bool) {
	return &v.get
}
func BridgeHandoverRequiredSourceToTargetTransparentContainerIEBindingFieldInfo(v *HandoverRequiredSourceToTargetTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredSourceToTargetTransparentContainerIEBindingFieldInject(v *HandoverRequiredSourceToTargetTransparentContainerIEBinding) *func(s00.SourceToTargetTransparentContainer) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeHandoverRequiredTargetIDIEBindingFieldCodec(v *HandoverRequiredTargetIDIEBinding) *TargetIDValueCodec {
	return &v.codec
}
func BridgeHandoverRequiredTargetIDIEBindingFieldGet(v *HandoverRequiredTargetIDIEBinding) *func(*HandoverRequiredIEValue) (*TargetID, bool) {
	return &v.get
}
func BridgeHandoverRequiredTargetIDIEBindingFieldInfo(v *HandoverRequiredTargetIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequiredTargetIDIEBindingFieldInject(v *HandoverRequiredTargetIDIEBinding) *func(TargetID) HandoverRequiredIEValue {
	return &v.inject
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingAPERValueFieldContext(v *InformationOnRecommendedCellsAndENBsForPagingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingAPERValueFieldReceived(v *InformationOnRecommendedCellsAndENBsForPagingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingAPERValueFieldReplay(v *InformationOnRecommendedCellsAndENBsForPagingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingAPERValueFieldWithoutReplay(v *InformationOnRecommendedCellsAndENBsForPagingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldExtCount(v *InformationOnRecommendedCellsAndENBsForPaging) *int64 {
	return &v.extCount
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldExtData(v *InformationOnRecommendedCellsAndENBsForPaging) *[][]byte {
	return &v.extData
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldExtOrigin(v *InformationOnRecommendedCellsAndENBsForPaging) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldExtPresent(v *InformationOnRecommendedCellsAndENBsForPaging) *[]bool {
	return &v.extPresent
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldExtWire(v *InformationOnRecommendedCellsAndENBsForPaging) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldIEExtensionsIndef(v *InformationOnRecommendedCellsAndENBsForPaging) *bool {
	return &v.iEExtensionsIndef
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldPerExtPadding(v *InformationOnRecommendedCellsAndENBsForPaging) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldPerPadding(v *InformationOnRecommendedCellsAndENBsForPaging) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceived(v *InformationOnRecommendedCellsAndENBsForPaging) *bool {
	return &v.received
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedAbsolute(v *InformationOnRecommendedCellsAndENBsForPaging) *bool {
	return &v.receivedAbsolute
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedBytes(v *InformationOnRecommendedCellsAndENBsForPaging) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReceivedLocation(v *InformationOnRecommendedCellsAndENBsForPaging) *aper.Location {
	return &v.receivedLocation
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldReplay(v *InformationOnRecommendedCellsAndENBsForPaging) *aper.Snapshot {
	return &v.replay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldStream(v *InformationOnRecommendedCellsAndENBsForPaging) *aper.WireSpan {
	return &v.stream
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingFieldWithoutReplay(v *InformationOnRecommendedCellsAndENBsForPaging) *bool {
	return &v.withoutReplay
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERBudget(v *InformationOnRecommendedCellsAndENBsForPaging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERBudgetValue(v *InformationOnRecommendedCellsAndENBsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERChanged(v *InformationOnRecommendedCellsAndENBsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERChangedValue(v *InformationOnRecommendedCellsAndENBsForPaging, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERLegacy(v *InformationOnRecommendedCellsAndENBsForPaging) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERNewValue(v *InformationOnRecommendedCellsAndENBsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERPlanned(v *InformationOnRecommendedCellsAndENBsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodMarshalAPERTo(v *InformationOnRecommendedCellsAndENBsForPaging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodUnmarshalAPERFrom(v *InformationOnRecommendedCellsAndENBsForPaging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodUnmarshalAPERLegacy(v *InformationOnRecommendedCellsAndENBsForPaging, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingMethodUnmarshalAPERWithOptions(v *InformationOnRecommendedCellsAndENBsForPaging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCapture(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *func(InformationOnRecommendedCellsAndENBsForPaging, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldCompare(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *func(InformationOnRecommendedCellsAndENBsForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldContext(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldDecode(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *func([]byte, aper.DecodeState) (InformationOnRecommendedCellsAndENBsForPaging, error) {
	return &v.decode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldEncode(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *func(InformationOnRecommendedCellsAndENBsForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecFieldPath(v *InformationOnRecommendedCellsAndENBsForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecMethodEncodeBudgetValue(v InformationOnRecommendedCellsAndENBsForPagingValueCodec, a0 InformationOnRecommendedCellsAndENBsForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInformationOnRecommendedCellsAndENBsForPagingValueCodecMethodEncodeChanged(v InformationOnRecommendedCellsAndENBsForPagingValueCodec, a0 InformationOnRecommendedCellsAndENBsForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterSystemInformationTransferTypeAPERValueFieldContext(v *InterSystemInformationTransferTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemInformationTransferTypeAPERValueFieldReceived(v *InterSystemInformationTransferTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterSystemInformationTransferTypeAPERValueFieldReplay(v *InterSystemInformationTransferTypeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemInformationTransferTypeAPERValueFieldWithoutReplay(v *InterSystemInformationTransferTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemInformationTransferTypeFieldPerOpenTypePadding(v *InterSystemInformationTransferType) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeInterSystemInformationTransferTypeFieldPerPadding(v *InterSystemInformationTransferType) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterSystemInformationTransferTypeFieldReceived(v *InterSystemInformationTransferType) *bool {
	return &v.received
}
func BridgeInterSystemInformationTransferTypeFieldReceivedAbsolute(v *InterSystemInformationTransferType) *bool {
	return &v.receivedAbsolute
}
func BridgeInterSystemInformationTransferTypeFieldReceivedBytes(v *InterSystemInformationTransferType) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterSystemInformationTransferTypeFieldReceivedLocation(v *InterSystemInformationTransferType) *aper.Location {
	return &v.receivedLocation
}
func BridgeInterSystemInformationTransferTypeFieldReplay(v *InterSystemInformationTransferType) *aper.Snapshot {
	return &v.replay
}
func BridgeInterSystemInformationTransferTypeFieldStream(v *InterSystemInformationTransferType) *aper.WireSpan {
	return &v.stream
}
func BridgeInterSystemInformationTransferTypeFieldWithoutReplay(v *InterSystemInformationTransferType) *bool {
	return &v.withoutReplay
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERBudget(v *InterSystemInformationTransferType, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERBudgetValue(v *InterSystemInformationTransferType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERChanged(v *InterSystemInformationTransferType, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERChangedValue(v *InterSystemInformationTransferType, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERLegacy(v *InterSystemInformationTransferType) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERNewValue(v *InterSystemInformationTransferType, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERPlanned(v *InterSystemInformationTransferType, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInterSystemInformationTransferTypeMethodMarshalAPERTo(v *InterSystemInformationTransferType, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterSystemInformationTransferTypeMethodUnmarshalAPERFrom(v *InterSystemInformationTransferType, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterSystemInformationTransferTypeMethodUnmarshalAPERLegacy(v *InterSystemInformationTransferType, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterSystemInformationTransferTypeMethodUnmarshalAPERWithOptions(v *InterSystemInformationTransferType, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldCapture(v *InterSystemInformationTransferTypeValueCodec) *func(InterSystemInformationTransferType, aper.DecodeState) (InterSystemInformationTransferType, aper.Snapshot) {
	return &v.capture
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldCompare(v *InterSystemInformationTransferTypeValueCodec) *func(InterSystemInformationTransferType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldContext(v *InterSystemInformationTransferTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldDecode(v *InterSystemInformationTransferTypeValueCodec) *func([]byte, aper.DecodeState) (InterSystemInformationTransferType, error) {
	return &v.decode
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldEncode(v *InterSystemInformationTransferTypeValueCodec) *func(InterSystemInformationTransferType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterSystemInformationTransferTypeValueCodecFieldPath(v *InterSystemInformationTransferTypeValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterSystemInformationTransferTypeValueCodecMethodEncodeBudgetValue(v InterSystemInformationTransferTypeValueCodec, a0 InterSystemInformationTransferType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInterSystemInformationTransferTypeValueCodecMethodEncodeChanged(v InterSystemInformationTransferTypeValueCodec, a0 InterSystemInformationTransferType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferAPERValueFieldContext(v *MMEDirectInformationTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferAPERValueFieldReceived(v *MMEDirectInformationTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferAPERValueFieldReplay(v *MMEDirectInformationTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferFieldExtCount(v *MMEDirectInformationTransfer) *int64 {
	return &v.extCount
}
func BridgeMMEDirectInformationTransferFieldExtData(v *MMEDirectInformationTransfer) *[][]byte {
	return &v.extData
}
func BridgeMMEDirectInformationTransferFieldExtOrigin(v *MMEDirectInformationTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEDirectInformationTransferFieldExtPresent(v *MMEDirectInformationTransfer) *[]bool {
	return &v.extPresent
}
func BridgeMMEDirectInformationTransferFieldExtWire(v *MMEDirectInformationTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMEDirectInformationTransferFieldPerExtPadding(v *MMEDirectInformationTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEDirectInformationTransferFieldPerPadding(v *MMEDirectInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEDirectInformationTransferFieldProtocolIEsIndef(v *MMEDirectInformationTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEDirectInformationTransferFieldReceived(v *MMEDirectInformationTransfer) *bool {
	return &v.received
}
func BridgeMMEDirectInformationTransferFieldReceivedAbsolute(v *MMEDirectInformationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEDirectInformationTransferFieldReceivedBytes(v *MMEDirectInformationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEDirectInformationTransferFieldReceivedLocation(v *MMEDirectInformationTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEDirectInformationTransferFieldReplay(v *MMEDirectInformationTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferFieldStream(v *MMEDirectInformationTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEDirectInformationTransferFieldWithoutReplay(v *MMEDirectInformationTransfer) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEContainerAPERValueFieldContext(v *MMEDirectInformationTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEContainerAPERValueFieldReceived(v *MMEDirectInformationTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEContainerAPERValueFieldReplay(v *MMEDirectInformationTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEContainerAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldCapture(v *MMEDirectInformationTransferIEContainerValueCodec) *func(MMEDirectInformationTransferIEContainer, aper.DecodeState) (MMEDirectInformationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldCompare(v *MMEDirectInformationTransferIEContainerValueCodec) *func(MMEDirectInformationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldContext(v *MMEDirectInformationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(v *MMEDirectInformationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldEncode(v *MMEDirectInformationTransferIEContainerValueCodec) *func(MMEDirectInformationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecFieldPath(v *MMEDirectInformationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferIEContainerValueCodec, a0 MMEDirectInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferIEContainerValueCodecMethodEncodeChanged(v MMEDirectInformationTransferIEContainerValueCodec, a0 MMEDirectInformationTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferIEFieldAPERValueFieldContext(v *MMEDirectInformationTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEFieldAPERValueFieldReceived(v *MMEDirectInformationTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEFieldAPERValueFieldReplay(v *MMEDirectInformationTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEFieldAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEFieldFieldReceived(v *MMEDirectInformationTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEFieldFieldReplay(v *MMEDirectInformationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEFieldFieldStream(v *MMEDirectInformationTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEDirectInformationTransferIEFieldFieldWithoutReplay(v *MMEDirectInformationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEFieldMethodMarshalAPERTo(v *MMEDirectInformationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(v *MMEDirectInformationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldCapture(v *MMEDirectInformationTransferIEFieldValueCodec) *func(MMEDirectInformationTransferIEField, aper.DecodeState) (MMEDirectInformationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldCompare(v *MMEDirectInformationTransferIEFieldValueCodec) *func(MMEDirectInformationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldContext(v *MMEDirectInformationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldDecode(v *MMEDirectInformationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEField, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldEncode(v *MMEDirectInformationTransferIEFieldValueCodec) *func(MMEDirectInformationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecFieldPath(v *MMEDirectInformationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferIEFieldValueCodec, a0 MMEDirectInformationTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferIEFieldValueCodecMethodEncodeChanged(v MMEDirectInformationTransferIEFieldValueCodec, a0 MMEDirectInformationTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferIETableMethodInfoInterSystemInformationTransferTypeMDT(v MMEDirectInformationTransferIETable) s00.FieldInfo {
	return v.infoInterSystemInformationTransferTypeMDT()
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListAPERValueFieldContext(v *MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListAPERValueFieldReceived(v *MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListAPERValueFieldReplay(v *MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueERABIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEDirectInformationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferIEValueERABIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEDirectInformationTransferIEValueERABIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferIEValueFieldId(v *MMEDirectInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEDirectInformationTransferIEValueFieldIsOpaque(v *MMEDirectInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEDirectInformationTransferIEValueFieldOpaque(v *MMEDirectInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEDirectInformationTransferIEValueFieldReceived(v *MMEDirectInformationTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEValueFieldReplay(v *MMEDirectInformationTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeMDT(v *MMEDirectInformationTransferIEValue) **InterSystemInformationTransferType {
	return &v.rowInterSystemInformationTransferTypeMDT
}
func BridgeMMEDirectInformationTransferIEValueMethodCaptureSemantics(v MMEDirectInformationTransferIEValue, a0 aper.SemanticCapture) MMEDirectInformationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEDirectInformationTransferIEValueMethodCompareSemantics(v MMEDirectInformationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEDirectInformationTransferIEValueMethodDecode(v MMEDirectInformationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEDirectInformationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEDirectInformationTransferIEValueMethodEncode(v MMEDirectInformationTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEDirectInformationTransferIEValueMethodEncodeFresh(v MMEDirectInformationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEDirectInformationTransferIEValueMethodMatchesID(v MMEDirectInformationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEDirectInformationTransferIEValueMethodReason(v MMEDirectInformationTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEDirectInformationTransferIEValueMethodRule(v MMEDirectInformationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEDirectInformationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec, a0 MMEDirectInformationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldCodec(v *MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *InterSystemInformationTransferTypeValueCodec {
	return &v.codec
}
func BridgeMMEDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldGet(v *MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *func(*MMEDirectInformationTransferIEValue) (*InterSystemInformationTransferType, bool) {
	return &v.get
}
func BridgeMMEDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldInfo(v *MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEDirectInformationTransferInterSystemInformationTransferTypeIEBindingFieldInject(v *MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding) *func(InterSystemInformationTransferType) MMEDirectInformationTransferIEValue {
	return &v.inject
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v *MMEDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERBudgetValue(v *MMEDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERChanged(v *MMEDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERChangedValue(v *MMEDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERLegacy(v *MMEDirectInformationTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERNewValue(v *MMEDirectInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERPlanned(v *MMEDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERTo(v *MMEDirectInformationTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEDirectInformationTransferMethodUnmarshalAPERFrom(v *MMEDirectInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEDirectInformationTransferMethodUnmarshalAPERLegacy(v *MMEDirectInformationTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEDirectInformationTransferMethodUnmarshalAPERWithOptions(v *MMEDirectInformationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEDirectInformationTransferValueCodecFieldCapture(v *MMEDirectInformationTransferValueCodec) *func(MMEDirectInformationTransfer, aper.DecodeState) (MMEDirectInformationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEDirectInformationTransferValueCodecFieldCompare(v *MMEDirectInformationTransferValueCodec) *func(MMEDirectInformationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEDirectInformationTransferValueCodecFieldContext(v *MMEDirectInformationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEDirectInformationTransferValueCodecFieldDecode(v *MMEDirectInformationTransferValueCodec) *func([]byte, aper.DecodeState) (MMEDirectInformationTransfer, error) {
	return &v.decode
}
func BridgeMMEDirectInformationTransferValueCodecFieldEncode(v *MMEDirectInformationTransferValueCodec) *func(MMEDirectInformationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEDirectInformationTransferValueCodecFieldPath(v *MMEDirectInformationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferValueCodecMethodEncodeBudgetValue(v MMEDirectInformationTransferValueCodec, a0 MMEDirectInformationTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEDirectInformationTransferValueCodecMethodEncodeChanged(v MMEDirectInformationTransferValueCodec, a0 MMEDirectInformationTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRIMRoutingAddressAPERValueFieldContext(v *RIMRoutingAddressAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMRoutingAddressAPERValueFieldReceived(v *RIMRoutingAddressAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRIMRoutingAddressAPERValueFieldReplay(v *RIMRoutingAddressAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRIMRoutingAddressAPERValueFieldWithoutReplay(v *RIMRoutingAddressAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRIMRoutingAddressFieldPerOpenTypePadding(v *RIMRoutingAddress) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeRIMRoutingAddressFieldPerPadding(v *RIMRoutingAddress) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeRIMRoutingAddressFieldReceived(v *RIMRoutingAddress) *bool { return &v.received }
func BridgeRIMRoutingAddressFieldReceivedAbsolute(v *RIMRoutingAddress) *bool {
	return &v.receivedAbsolute
}
func BridgeRIMRoutingAddressFieldReceivedBytes(v *RIMRoutingAddress) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRIMRoutingAddressFieldReceivedLocation(v *RIMRoutingAddress) *aper.Location {
	return &v.receivedLocation
}
func BridgeRIMRoutingAddressFieldReplay(v *RIMRoutingAddress) *aper.Snapshot { return &v.replay }
func BridgeRIMRoutingAddressFieldStream(v *RIMRoutingAddress) *aper.WireSpan { return &v.stream }
func BridgeRIMRoutingAddressFieldWithoutReplay(v *RIMRoutingAddress) *bool   { return &v.withoutReplay }
func BridgeRIMRoutingAddressMethodMarshalAPERBudget(v *RIMRoutingAddress, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRIMRoutingAddressMethodMarshalAPERBudgetValue(v *RIMRoutingAddress, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRIMRoutingAddressMethodMarshalAPERChanged(v *RIMRoutingAddress, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRIMRoutingAddressMethodMarshalAPERChangedValue(v *RIMRoutingAddress, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRIMRoutingAddressMethodMarshalAPERLegacy(v *RIMRoutingAddress) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRIMRoutingAddressMethodMarshalAPERNewValue(v *RIMRoutingAddress, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRIMRoutingAddressMethodMarshalAPERPlanned(v *RIMRoutingAddress, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRIMRoutingAddressMethodMarshalAPERTo(v *RIMRoutingAddress, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRIMRoutingAddressMethodUnmarshalAPERFrom(v *RIMRoutingAddress, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRIMRoutingAddressMethodUnmarshalAPERLegacy(v *RIMRoutingAddress, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRIMRoutingAddressMethodUnmarshalAPERWithOptions(v *RIMRoutingAddress, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRIMRoutingAddressValueCodecFieldCapture(v *RIMRoutingAddressValueCodec) *func(RIMRoutingAddress, aper.DecodeState) (RIMRoutingAddress, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMRoutingAddressValueCodecFieldCompare(v *RIMRoutingAddressValueCodec) *func(RIMRoutingAddress, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMRoutingAddressValueCodecFieldContext(v *RIMRoutingAddressValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMRoutingAddressValueCodecFieldDecode(v *RIMRoutingAddressValueCodec) *func([]byte, aper.DecodeState) (RIMRoutingAddress, error) {
	return &v.decode
}
func BridgeRIMRoutingAddressValueCodecFieldEncode(v *RIMRoutingAddressValueCodec) *func(RIMRoutingAddress, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMRoutingAddressValueCodecFieldPath(v *RIMRoutingAddressValueCodec) *aper.Path {
	return &v.path
}
func BridgeRIMRoutingAddressValueCodecMethodEncodeBudgetValue(v RIMRoutingAddressValueCodec, a0 RIMRoutingAddress, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRIMRoutingAddressValueCodecMethodEncodeChanged(v RIMRoutingAddressValueCodec, a0 RIMRoutingAddress, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRIMTransferAPERValueFieldContext(v *RIMTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMTransferAPERValueFieldReceived(v *RIMTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRIMTransferAPERValueFieldReplay(v *RIMTransferAPERValue) *aper.Snapshot { return &v.replay }
func BridgeRIMTransferAPERValueFieldWithoutReplay(v *RIMTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRIMTransferFieldExtCount(v *RIMTransfer) *int64                { return &v.extCount }
func BridgeRIMTransferFieldExtData(v *RIMTransfer) *[][]byte              { return &v.extData }
func BridgeRIMTransferFieldExtOrigin(v *RIMTransfer) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeRIMTransferFieldExtPresent(v *RIMTransfer) *[]bool             { return &v.extPresent }
func BridgeRIMTransferFieldExtWire(v *RIMTransfer) *[]aper.WireSpan       { return &v.extWire }
func BridgeRIMTransferFieldIEExtensionsIndef(v *RIMTransfer) *bool        { return &v.iEExtensionsIndef }
func BridgeRIMTransferFieldPerExtPadding(v *RIMTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRIMTransferFieldPerPadding(v *RIMTransfer) *aper.FinalPadding { return &v.perPadding }
func BridgeRIMTransferFieldReceived(v *RIMTransfer) *bool                { return &v.received }
func BridgeRIMTransferFieldReceivedAbsolute(v *RIMTransfer) *bool        { return &v.receivedAbsolute }
func BridgeRIMTransferFieldReceivedBytes(v *RIMTransfer) *aper.WireSpan  { return &v.receivedBytes }
func BridgeRIMTransferFieldReceivedLocation(v *RIMTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeRIMTransferFieldReplay(v *RIMTransfer) *aper.Snapshot { return &v.replay }
func BridgeRIMTransferFieldStream(v *RIMTransfer) *aper.WireSpan { return &v.stream }
func BridgeRIMTransferFieldWithoutReplay(v *RIMTransfer) *bool   { return &v.withoutReplay }
func BridgeRIMTransferMethodMarshalAPERBudget(v *RIMTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRIMTransferMethodMarshalAPERBudgetValue(v *RIMTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRIMTransferMethodMarshalAPERChanged(v *RIMTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRIMTransferMethodMarshalAPERChangedValue(v *RIMTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRIMTransferMethodMarshalAPERLegacy(v *RIMTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRIMTransferMethodMarshalAPERNewValue(v *RIMTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRIMTransferMethodMarshalAPERPlanned(v *RIMTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRIMTransferMethodMarshalAPERTo(v *RIMTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRIMTransferMethodUnmarshalAPERFrom(v *RIMTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRIMTransferMethodUnmarshalAPERLegacy(v *RIMTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRIMTransferMethodUnmarshalAPERWithOptions(v *RIMTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRIMTransferValueCodecFieldCapture(v *RIMTransferValueCodec) *func(RIMTransfer, aper.DecodeState) (RIMTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMTransferValueCodecFieldCompare(v *RIMTransferValueCodec) *func(RIMTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMTransferValueCodecFieldContext(v *RIMTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMTransferValueCodecFieldDecode(v *RIMTransferValueCodec) *func([]byte, aper.DecodeState) (RIMTransfer, error) {
	return &v.decode
}
func BridgeRIMTransferValueCodecFieldEncode(v *RIMTransferValueCodec) *func(RIMTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMTransferValueCodecFieldPath(v *RIMTransferValueCodec) *aper.Path { return &v.path }
func BridgeRIMTransferValueCodecMethodEncodeBudgetValue(v RIMTransferValueCodec, a0 RIMTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRIMTransferValueCodecMethodEncodeChanged(v RIMTransferValueCodec, a0 RIMTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRecommendedENBsForPagingAPERValueFieldContext(v *RecommendedENBsForPagingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBsForPagingAPERValueFieldReceived(v *RecommendedENBsForPagingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRecommendedENBsForPagingAPERValueFieldReplay(v *RecommendedENBsForPagingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBsForPagingAPERValueFieldWithoutReplay(v *RecommendedENBsForPagingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBsForPagingValueCodecFieldCapture(v *RecommendedENBsForPagingValueCodec) *func(s33.RecommendedENBsForPaging, aper.DecodeState) (s33.RecommendedENBsForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBsForPagingValueCodecFieldCompare(v *RecommendedENBsForPagingValueCodec) *func(s33.RecommendedENBsForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBsForPagingValueCodecFieldContext(v *RecommendedENBsForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBsForPagingValueCodecFieldDecode(v *RecommendedENBsForPagingValueCodec) *func([]byte, aper.DecodeState) (s33.RecommendedENBsForPaging, error) {
	return &v.decode
}
func BridgeRecommendedENBsForPagingValueCodecFieldEncode(v *RecommendedENBsForPagingValueCodec) *func(s33.RecommendedENBsForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBsForPagingValueCodecFieldPath(v *RecommendedENBsForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBsForPagingValueCodecMethodEncodeBudgetValue(v RecommendedENBsForPagingValueCodec, a0 s33.RecommendedENBsForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedENBsForPagingValueCodecMethodEncodeChanged(v RecommendedENBsForPagingValueCodec, a0 s33.RecommendedENBsForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemAPERValueFieldContext(v *TAIItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemAPERValueFieldReceived(v *TAIItemAPERValue) *aper.WireSpan { return &v.received }
func BridgeTAIItemAPERValueFieldReplay(v *TAIItemAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeTAIItemAPERValueFieldWithoutReplay(v *TAIItemAPERValue) *bool     { return &v.withoutReplay }
func BridgeTAIItemFieldExtCount(v *TAIItem) *int64                           { return &v.extCount }
func BridgeTAIItemFieldExtData(v *TAIItem) *[][]byte                         { return &v.extData }
func BridgeTAIItemFieldExtOrigin(v *TAIItem) *[]aper.OpaqueOrigin            { return &v.extOrigin }
func BridgeTAIItemFieldExtPresent(v *TAIItem) *[]bool                        { return &v.extPresent }
func BridgeTAIItemFieldExtWire(v *TAIItem) *[]aper.WireSpan                  { return &v.extWire }
func BridgeTAIItemFieldIEExtensionsIndef(v *TAIItem) *bool                   { return &v.iEExtensionsIndef }
func BridgeTAIItemFieldPerExtPadding(v *TAIItem) *[]aper.CompletePadding     { return &v.perExtPadding }
func BridgeTAIItemFieldPerPadding(v *TAIItem) *aper.FinalPadding             { return &v.perPadding }
func BridgeTAIItemFieldReceived(v *TAIItem) *bool                            { return &v.received }
func BridgeTAIItemFieldReceivedAbsolute(v *TAIItem) *bool                    { return &v.receivedAbsolute }
func BridgeTAIItemFieldReceivedBytes(v *TAIItem) *aper.WireSpan              { return &v.receivedBytes }
func BridgeTAIItemFieldReceivedLocation(v *TAIItem) *aper.Location           { return &v.receivedLocation }
func BridgeTAIItemFieldReplay(v *TAIItem) *aper.Snapshot                     { return &v.replay }
func BridgeTAIItemFieldStream(v *TAIItem) *aper.WireSpan                     { return &v.stream }
func BridgeTAIItemFieldWithoutReplay(v *TAIItem) *bool                       { return &v.withoutReplay }
func BridgeTAIItemIEContainerAPERValueFieldContext(v *TAIItemIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEContainerAPERValueFieldReceived(v *TAIItemIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIItemIEContainerAPERValueFieldReplay(v *TAIItemIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemIEContainerAPERValueFieldWithoutReplay(v *TAIItemIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemIEContainerValueCodecFieldCapture(v *TAIItemIEContainerValueCodec) *func(TAIItemIEContainer, aper.DecodeState) (TAIItemIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemIEContainerValueCodecFieldCompare(v *TAIItemIEContainerValueCodec) *func(TAIItemIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemIEContainerValueCodecFieldContext(v *TAIItemIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEContainerValueCodecFieldDecode(v *TAIItemIEContainerValueCodec) *func([]byte, aper.DecodeState) (TAIItemIEContainer, error) {
	return &v.decode
}
func BridgeTAIItemIEContainerValueCodecFieldEncode(v *TAIItemIEContainerValueCodec) *func(TAIItemIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemIEContainerValueCodecFieldPath(v *TAIItemIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemIEContainerValueCodecMethodEncodeBudgetValue(v TAIItemIEContainerValueCodec, a0 TAIItemIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemIEContainerValueCodecMethodEncodeChanged(v TAIItemIEContainerValueCodec, a0 TAIItemIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemIEFieldAPERValueFieldContext(v *TAIItemIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEFieldAPERValueFieldReceived(v *TAIItemIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIItemIEFieldAPERValueFieldReplay(v *TAIItemIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemIEFieldAPERValueFieldWithoutReplay(v *TAIItemIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemIEFieldFieldReceived(v *TAIItemIEField) *aper.CompletePadding { return &v.received }
func BridgeTAIItemIEFieldFieldReplay(v *TAIItemIEField) *aper.Snapshot          { return &v.replay }
func BridgeTAIItemIEFieldFieldStream(v *TAIItemIEField) *aper.WireSpan          { return &v.stream }
func BridgeTAIItemIEFieldFieldWithoutReplay(v *TAIItemIEField) *bool            { return &v.withoutReplay }
func BridgeTAIItemIEFieldMethodMarshalAPERTo(v *TAIItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIItemIEFieldMethodUnmarshalAPERFrom(v *TAIItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIItemIEFieldValueCodecFieldCapture(v *TAIItemIEFieldValueCodec) *func(TAIItemIEField, aper.DecodeState) (TAIItemIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemIEFieldValueCodecFieldCompare(v *TAIItemIEFieldValueCodec) *func(TAIItemIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemIEFieldValueCodecFieldContext(v *TAIItemIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEFieldValueCodecFieldDecode(v *TAIItemIEFieldValueCodec) *func([]byte, aper.DecodeState) (TAIItemIEField, error) {
	return &v.decode
}
func BridgeTAIItemIEFieldValueCodecFieldEncode(v *TAIItemIEFieldValueCodec) *func(TAIItemIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemIEFieldValueCodecFieldPath(v *TAIItemIEFieldValueCodec) *aper.Path { return &v.path }
func BridgeTAIItemIEFieldValueCodecMethodEncodeBudgetValue(v TAIItemIEFieldValueCodec, a0 TAIItemIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemIEFieldValueCodecMethodEncodeChanged(v TAIItemIEFieldValueCodec, a0 TAIItemIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemIETableMethodInfoTAIItem(v TAIItemIETable) s00.FieldInfo { return v.infoTAIItem() }
func BridgeTAIItemIEValueERABIEContainerListAPERValueFieldContext(v *TAIItemIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueERABIEContainerListAPERValueFieldReceived(v *TAIItemIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIItemIEValueERABIEContainerListAPERValueFieldReplay(v *TAIItemIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *TAIItemIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldCapture(v *TAIItemIEValueERABIEContainerListValueCodec) *func(TAIItemIEValueERABIEContainerList, aper.DecodeState) (TAIItemIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldCompare(v *TAIItemIEValueERABIEContainerListValueCodec) *func(TAIItemIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldContext(v *TAIItemIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldDecode(v *TAIItemIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TAIItemIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldEncode(v *TAIItemIEValueERABIEContainerListValueCodec) *func(TAIItemIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecFieldPath(v *TAIItemIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v TAIItemIEValueERABIEContainerListValueCodec, a0 TAIItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemIEValueERABIEContainerListValueCodecMethodEncodeChanged(v TAIItemIEValueERABIEContainerListValueCodec, a0 TAIItemIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemIEValueFieldId(v *TAIItemIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgeTAIItemIEValueFieldIsOpaque(v *TAIItemIEValue) *bool              { return &v.isOpaque }
func BridgeTAIItemIEValueFieldOpaque(v *TAIItemIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeTAIItemIEValueFieldReceived(v *TAIItemIEValue) *aper.WireSpan     { return &v.received }
func BridgeTAIItemIEValueFieldReplay(v *TAIItemIEValue) *aper.Snapshot       { return &v.replay }
func BridgeTAIItemIEValueFieldRowTAIItem(v *TAIItemIEValue) **TAIItem        { return &v.rowTAIItem }
func BridgeTAIItemIEValueMethodCaptureSemantics(v TAIItemIEValue, a0 aper.SemanticCapture) TAIItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeTAIItemIEValueMethodCompareSemantics(v TAIItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTAIItemIEValueMethodDecode(v TAIItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (TAIItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeTAIItemIEValueMethodEncode(v TAIItemIEValue) ([]byte, error) { return v.encode() }
func BridgeTAIItemIEValueMethodEncodeFresh(v TAIItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTAIItemIEValueMethodMatchesID(v TAIItemIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeTAIItemIEValueMethodReason(v TAIItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeTAIItemIEValueMethodRule(v TAIItemIEValue) aper.SourceRule { return v.rule() }
func BridgeTAIItemIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *TAIItemIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *TAIItemIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *TAIItemIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *TAIItemIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *func(TAIItemIEValueProtocolErrorIEContainerList, aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *func(TAIItemIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *func(TAIItemIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *TAIItemIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v TAIItemIEValueProtocolErrorIEContainerListValueCodec, a0 TAIItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v TAIItemIEValueProtocolErrorIEContainerListValueCodec, a0 TAIItemIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemIEValueProtocolIEContainerListAPERValueFieldContext(v *TAIItemIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueProtocolIEContainerListAPERValueFieldReceived(v *TAIItemIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTAIItemIEValueProtocolIEContainerListAPERValueFieldReplay(v *TAIItemIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIItemIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *TAIItemIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldCapture(v *TAIItemIEValueProtocolIEContainerListValueCodec) *func(TAIItemIEValueProtocolIEContainerList, aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldCompare(v *TAIItemIEValueProtocolIEContainerListValueCodec) *func(TAIItemIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldContext(v *TAIItemIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldDecode(v *TAIItemIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldEncode(v *TAIItemIEValueProtocolIEContainerListValueCodec) *func(TAIItemIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecFieldPath(v *TAIItemIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v TAIItemIEValueProtocolIEContainerListValueCodec, a0 TAIItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v TAIItemIEValueProtocolIEContainerListValueCodec, a0 TAIItemIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIItemMethodMarshalAPERBudget(v *TAIItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIItemMethodMarshalAPERBudgetValue(v *TAIItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIItemMethodMarshalAPERChanged(v *TAIItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIItemMethodMarshalAPERChangedValue(v *TAIItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIItemMethodMarshalAPERLegacy(v *TAIItem) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeTAIItemMethodMarshalAPERNewValue(v *TAIItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIItemMethodMarshalAPERPlanned(v *TAIItem, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIItemMethodMarshalAPERTo(v *TAIItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTAIItemMethodUnmarshalAPERFrom(v *TAIItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTAIItemMethodUnmarshalAPERLegacy(v *TAIItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIItemMethodUnmarshalAPERWithOptions(v *TAIItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIItemTAIItemIEBindingFieldCodec(v *TAIItemTAIItemIEBinding) *TAIItemValueCodec {
	return &v.codec
}
func BridgeTAIItemTAIItemIEBindingFieldGet(v *TAIItemTAIItemIEBinding) *func(*TAIItemIEValue) (*TAIItem, bool) {
	return &v.get
}
func BridgeTAIItemTAIItemIEBindingFieldInfo(v *TAIItemTAIItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeTAIItemTAIItemIEBindingFieldInject(v *TAIItemTAIItemIEBinding) *func(TAIItem) TAIItemIEValue {
	return &v.inject
}
func BridgeTAIItemValueCodecFieldCapture(v *TAIItemValueCodec) *func(TAIItem, aper.DecodeState) (TAIItem, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIItemValueCodecFieldCompare(v *TAIItemValueCodec) *func(TAIItem, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIItemValueCodecFieldContext(v *TAIItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIItemValueCodecFieldDecode(v *TAIItemValueCodec) *func([]byte, aper.DecodeState) (TAIItem, error) {
	return &v.decode
}
func BridgeTAIItemValueCodecFieldEncode(v *TAIItemValueCodec) *func(TAIItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIItemValueCodecFieldPath(v *TAIItemValueCodec) *aper.Path { return &v.path }
func BridgeTAIItemValueCodecMethodEncodeBudgetValue(v TAIItemValueCodec, a0 TAIItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIItemValueCodecMethodEncodeChanged(v TAIItemValueCodec, a0 TAIItem, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTAIListAPERValueFieldContext(v *TAIListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListAPERValueFieldReceived(v *TAIListAPERValue) *aper.WireSpan { return &v.received }
func BridgeTAIListAPERValueFieldReplay(v *TAIListAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeTAIListAPERValueFieldWithoutReplay(v *TAIListAPERValue) *bool     { return &v.withoutReplay }
func BridgeTAIListValueCodecFieldCapture(v *TAIListValueCodec) *func(TAIList, aper.DecodeState) (TAIList, aper.Snapshot) {
	return &v.capture
}
func BridgeTAIListValueCodecFieldCompare(v *TAIListValueCodec) *func(TAIList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAIListValueCodecFieldContext(v *TAIListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAIListValueCodecFieldDecode(v *TAIListValueCodec) *func([]byte, aper.DecodeState) (TAIList, error) {
	return &v.decode
}
func BridgeTAIListValueCodecFieldEncode(v *TAIListValueCodec) *func(TAIList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAIListValueCodecFieldPath(v *TAIListValueCodec) *aper.Path { return &v.path }
func BridgeTAIListValueCodecMethodEncodeBudgetValue(v TAIListValueCodec, a0 TAIList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTAIListValueCodecMethodEncodeChanged(v TAIListValueCodec, a0 TAIList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargetIDAPERValueFieldContext(v *TargetIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetIDAPERValueFieldReceived(v *TargetIDAPERValue) *aper.WireSpan { return &v.received }
func BridgeTargetIDAPERValueFieldReplay(v *TargetIDAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeTargetIDAPERValueFieldWithoutReplay(v *TargetIDAPERValue) *bool     { return &v.withoutReplay }
func BridgeTargetIDFieldPerOpenTypePadding(v *TargetID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeTargetIDFieldPerPadding(v *TargetID) *aper.CompletePadding { return &v.perPadding }
func BridgeTargetIDFieldReceived(v *TargetID) *bool                   { return &v.received }
func BridgeTargetIDFieldReceivedAbsolute(v *TargetID) *bool           { return &v.receivedAbsolute }
func BridgeTargetIDFieldReceivedBytes(v *TargetID) *aper.WireSpan     { return &v.receivedBytes }
func BridgeTargetIDFieldReceivedLocation(v *TargetID) *aper.Location  { return &v.receivedLocation }
func BridgeTargetIDFieldReplay(v *TargetID) *aper.Snapshot            { return &v.replay }
func BridgeTargetIDFieldStream(v *TargetID) *aper.WireSpan            { return &v.stream }
func BridgeTargetIDFieldWithoutReplay(v *TargetID) *bool              { return &v.withoutReplay }
func BridgeTargetIDMethodMarshalAPERBudget(v *TargetID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTargetIDMethodMarshalAPERBudgetValue(v *TargetID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTargetIDMethodMarshalAPERChanged(v *TargetID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTargetIDMethodMarshalAPERChangedValue(v *TargetID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTargetIDMethodMarshalAPERLegacy(v *TargetID) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeTargetIDMethodMarshalAPERNewValue(v *TargetID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTargetIDMethodMarshalAPERPlanned(v *TargetID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTargetIDMethodMarshalAPERTo(v *TargetID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargetIDMethodUnmarshalAPERFrom(v *TargetID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargetIDMethodUnmarshalAPERLegacy(v *TargetID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTargetIDMethodUnmarshalAPERWithOptions(v *TargetID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTargetIDValueCodecFieldCapture(v *TargetIDValueCodec) *func(TargetID, aper.DecodeState) (TargetID, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetIDValueCodecFieldCompare(v *TargetIDValueCodec) *func(TargetID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetIDValueCodecFieldContext(v *TargetIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetIDValueCodecFieldDecode(v *TargetIDValueCodec) *func([]byte, aper.DecodeState) (TargetID, error) {
	return &v.decode
}
func BridgeTargetIDValueCodecFieldEncode(v *TargetIDValueCodec) *func(TargetID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetIDValueCodecFieldPath(v *TargetIDValueCodec) *aper.Path { return &v.path }
func BridgeTargetIDValueCodecMethodEncodeBudgetValue(v TargetIDValueCodec, a0 TargetID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargetIDValueCodecMethodEncodeChanged(v TargetIDValueCodec, a0 TargetID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargetNgRanNodeIDAPERValueFieldContext(v *TargetNgRanNodeIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetNgRanNodeIDAPERValueFieldReceived(v *TargetNgRanNodeIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargetNgRanNodeIDAPERValueFieldReplay(v *TargetNgRanNodeIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTargetNgRanNodeIDAPERValueFieldWithoutReplay(v *TargetNgRanNodeIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargetNgRanNodeIDFieldExtCount(v *TargetNgRanNodeID) *int64   { return &v.extCount }
func BridgeTargetNgRanNodeIDFieldExtData(v *TargetNgRanNodeID) *[][]byte { return &v.extData }
func BridgeTargetNgRanNodeIDFieldExtOrigin(v *TargetNgRanNodeID) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTargetNgRanNodeIDFieldExtPresent(v *TargetNgRanNodeID) *[]bool       { return &v.extPresent }
func BridgeTargetNgRanNodeIDFieldExtWire(v *TargetNgRanNodeID) *[]aper.WireSpan { return &v.extWire }
func BridgeTargetNgRanNodeIDFieldIEExtensionsIndef(v *TargetNgRanNodeID) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTargetNgRanNodeIDFieldPerExtPadding(v *TargetNgRanNodeID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTargetNgRanNodeIDFieldPerPadding(v *TargetNgRanNodeID) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTargetNgRanNodeIDFieldReceived(v *TargetNgRanNodeID) *bool { return &v.received }
func BridgeTargetNgRanNodeIDFieldReceivedAbsolute(v *TargetNgRanNodeID) *bool {
	return &v.receivedAbsolute
}
func BridgeTargetNgRanNodeIDFieldReceivedBytes(v *TargetNgRanNodeID) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTargetNgRanNodeIDFieldReceivedLocation(v *TargetNgRanNodeID) *aper.Location {
	return &v.receivedLocation
}
func BridgeTargetNgRanNodeIDFieldReplay(v *TargetNgRanNodeID) *aper.Snapshot { return &v.replay }
func BridgeTargetNgRanNodeIDFieldStream(v *TargetNgRanNodeID) *aper.WireSpan { return &v.stream }
func BridgeTargetNgRanNodeIDFieldWithoutReplay(v *TargetNgRanNodeID) *bool   { return &v.withoutReplay }
func BridgeTargetNgRanNodeIDMethodMarshalAPERBudget(v *TargetNgRanNodeID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERBudgetValue(v *TargetNgRanNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERChanged(v *TargetNgRanNodeID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERChangedValue(v *TargetNgRanNodeID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERLegacy(v *TargetNgRanNodeID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERNewValue(v *TargetNgRanNodeID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERPlanned(v *TargetNgRanNodeID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTargetNgRanNodeIDMethodMarshalAPERTo(v *TargetNgRanNodeID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargetNgRanNodeIDMethodUnmarshalAPERFrom(v *TargetNgRanNodeID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargetNgRanNodeIDMethodUnmarshalAPERLegacy(v *TargetNgRanNodeID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTargetNgRanNodeIDMethodUnmarshalAPERWithOptions(v *TargetNgRanNodeID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTargetNgRanNodeIDValueCodecFieldCapture(v *TargetNgRanNodeIDValueCodec) *func(TargetNgRanNodeID, aper.DecodeState) (TargetNgRanNodeID, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetNgRanNodeIDValueCodecFieldCompare(v *TargetNgRanNodeIDValueCodec) *func(TargetNgRanNodeID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetNgRanNodeIDValueCodecFieldContext(v *TargetNgRanNodeIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetNgRanNodeIDValueCodecFieldDecode(v *TargetNgRanNodeIDValueCodec) *func([]byte, aper.DecodeState) (TargetNgRanNodeID, error) {
	return &v.decode
}
func BridgeTargetNgRanNodeIDValueCodecFieldEncode(v *TargetNgRanNodeIDValueCodec) *func(TargetNgRanNodeID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetNgRanNodeIDValueCodecFieldPath(v *TargetNgRanNodeIDValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetNgRanNodeIDValueCodecMethodEncodeBudgetValue(v TargetNgRanNodeIDValueCodec, a0 TargetNgRanNodeID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargetNgRanNodeIDValueCodecMethodEncodeChanged(v TargetNgRanNodeIDValueCodec, a0 TargetNgRanNodeID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargetRNCIDAPERValueFieldContext(v *TargetRNCIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCIDAPERValueFieldReceived(v *TargetRNCIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargetRNCIDAPERValueFieldReplay(v *TargetRNCIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTargetRNCIDAPERValueFieldWithoutReplay(v *TargetRNCIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargetRNCIDFieldExtCount(v *TargetRNCID) *int64                { return &v.extCount }
func BridgeTargetRNCIDFieldExtData(v *TargetRNCID) *[][]byte              { return &v.extData }
func BridgeTargetRNCIDFieldExtOrigin(v *TargetRNCID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTargetRNCIDFieldExtPresent(v *TargetRNCID) *[]bool             { return &v.extPresent }
func BridgeTargetRNCIDFieldExtWire(v *TargetRNCID) *[]aper.WireSpan       { return &v.extWire }
func BridgeTargetRNCIDFieldIEExtensionsIndef(v *TargetRNCID) *bool        { return &v.iEExtensionsIndef }
func BridgeTargetRNCIDFieldPerExtPadding(v *TargetRNCID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTargetRNCIDFieldPerPadding(v *TargetRNCID) *aper.FinalPadding { return &v.perPadding }
func BridgeTargetRNCIDFieldReceived(v *TargetRNCID) *bool                { return &v.received }
func BridgeTargetRNCIDFieldReceivedAbsolute(v *TargetRNCID) *bool        { return &v.receivedAbsolute }
func BridgeTargetRNCIDFieldReceivedBytes(v *TargetRNCID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeTargetRNCIDFieldReceivedLocation(v *TargetRNCID) *aper.Location {
	return &v.receivedLocation
}
func BridgeTargetRNCIDFieldReplay(v *TargetRNCID) *aper.Snapshot { return &v.replay }
func BridgeTargetRNCIDFieldStream(v *TargetRNCID) *aper.WireSpan { return &v.stream }
func BridgeTargetRNCIDFieldWithoutReplay(v *TargetRNCID) *bool   { return &v.withoutReplay }
func BridgeTargetRNCIDMethodMarshalAPERBudget(v *TargetRNCID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTargetRNCIDMethodMarshalAPERBudgetValue(v *TargetRNCID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTargetRNCIDMethodMarshalAPERChanged(v *TargetRNCID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTargetRNCIDMethodMarshalAPERChangedValue(v *TargetRNCID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTargetRNCIDMethodMarshalAPERLegacy(v *TargetRNCID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTargetRNCIDMethodMarshalAPERNewValue(v *TargetRNCID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTargetRNCIDMethodMarshalAPERPlanned(v *TargetRNCID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTargetRNCIDMethodMarshalAPERTo(v *TargetRNCID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargetRNCIDMethodUnmarshalAPERFrom(v *TargetRNCID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargetRNCIDMethodUnmarshalAPERLegacy(v *TargetRNCID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTargetRNCIDMethodUnmarshalAPERWithOptions(v *TargetRNCID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTargetRNCIDValueCodecFieldCapture(v *TargetRNCIDValueCodec) *func(TargetRNCID, aper.DecodeState) (TargetRNCID, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetRNCIDValueCodecFieldCompare(v *TargetRNCIDValueCodec) *func(TargetRNCID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetRNCIDValueCodecFieldContext(v *TargetRNCIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCIDValueCodecFieldDecode(v *TargetRNCIDValueCodec) *func([]byte, aper.DecodeState) (TargetRNCID, error) {
	return &v.decode
}
func BridgeTargetRNCIDValueCodecFieldEncode(v *TargetRNCIDValueCodec) *func(TargetRNCID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetRNCIDValueCodecFieldPath(v *TargetRNCIDValueCodec) *aper.Path { return &v.path }
func BridgeTargetRNCIDValueCodecMethodEncodeBudgetValue(v TargetRNCIDValueCodec, a0 TargetRNCID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargetRNCIDValueCodecMethodEncodeChanged(v TargetRNCIDValueCodec, a0 TargetRNCID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTargeteNBIDAPERValueFieldContext(v *TargeteNBIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBIDAPERValueFieldReceived(v *TargeteNBIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTargeteNBIDAPERValueFieldReplay(v *TargeteNBIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTargeteNBIDAPERValueFieldWithoutReplay(v *TargeteNBIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTargeteNBIDFieldExtCount(v *TargeteNBID) *int64                { return &v.extCount }
func BridgeTargeteNBIDFieldExtData(v *TargeteNBID) *[][]byte              { return &v.extData }
func BridgeTargeteNBIDFieldExtOrigin(v *TargeteNBID) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTargeteNBIDFieldExtPresent(v *TargeteNBID) *[]bool             { return &v.extPresent }
func BridgeTargeteNBIDFieldExtWire(v *TargeteNBID) *[]aper.WireSpan       { return &v.extWire }
func BridgeTargeteNBIDFieldIEExtensionsIndef(v *TargeteNBID) *bool        { return &v.iEExtensionsIndef }
func BridgeTargeteNBIDFieldPerExtPadding(v *TargeteNBID) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTargeteNBIDFieldPerPadding(v *TargeteNBID) *aper.FinalPadding { return &v.perPadding }
func BridgeTargeteNBIDFieldReceived(v *TargeteNBID) *bool                { return &v.received }
func BridgeTargeteNBIDFieldReceivedAbsolute(v *TargeteNBID) *bool        { return &v.receivedAbsolute }
func BridgeTargeteNBIDFieldReceivedBytes(v *TargeteNBID) *aper.WireSpan  { return &v.receivedBytes }
func BridgeTargeteNBIDFieldReceivedLocation(v *TargeteNBID) *aper.Location {
	return &v.receivedLocation
}
func BridgeTargeteNBIDFieldReplay(v *TargeteNBID) *aper.Snapshot { return &v.replay }
func BridgeTargeteNBIDFieldStream(v *TargeteNBID) *aper.WireSpan { return &v.stream }
func BridgeTargeteNBIDFieldWithoutReplay(v *TargeteNBID) *bool   { return &v.withoutReplay }
func BridgeTargeteNBIDMethodMarshalAPERBudget(v *TargeteNBID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTargeteNBIDMethodMarshalAPERBudgetValue(v *TargeteNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTargeteNBIDMethodMarshalAPERChanged(v *TargeteNBID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTargeteNBIDMethodMarshalAPERChangedValue(v *TargeteNBID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTargeteNBIDMethodMarshalAPERLegacy(v *TargeteNBID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTargeteNBIDMethodMarshalAPERNewValue(v *TargeteNBID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTargeteNBIDMethodMarshalAPERPlanned(v *TargeteNBID, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTargeteNBIDMethodMarshalAPERTo(v *TargeteNBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBIDMethodUnmarshalAPERFrom(v *TargeteNBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTargeteNBIDMethodUnmarshalAPERLegacy(v *TargeteNBID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTargeteNBIDMethodUnmarshalAPERWithOptions(v *TargeteNBID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTargeteNBIDValueCodecFieldCapture(v *TargeteNBIDValueCodec) *func(TargeteNBID, aper.DecodeState) (TargeteNBID, aper.Snapshot) {
	return &v.capture
}
func BridgeTargeteNBIDValueCodecFieldCompare(v *TargeteNBIDValueCodec) *func(TargeteNBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargeteNBIDValueCodecFieldContext(v *TargeteNBIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargeteNBIDValueCodecFieldDecode(v *TargeteNBIDValueCodec) *func([]byte, aper.DecodeState) (TargeteNBID, error) {
	return &v.decode
}
func BridgeTargeteNBIDValueCodecFieldEncode(v *TargeteNBIDValueCodec) *func(TargeteNBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargeteNBIDValueCodecFieldPath(v *TargeteNBIDValueCodec) *aper.Path { return &v.path }
func BridgeTargeteNBIDValueCodecMethodEncodeBudgetValue(v TargeteNBIDValueCodec, a0 TargeteNBID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargeteNBIDValueCodecMethodEncodeChanged(v TargeteNBIDValueCodec, a0 TargeteNBID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBDirectInformationTransferIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 121:
		if value, ok := v.AsInterSystemInformationTransferTypeEDT(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverRequiredIEValue) Selected() (any, bool) {
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
	case 1:
		if value, ok := v.AsHandoverType(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	case 4:
		if value, ok := v.AsTargetID(); ok {
			return value, true
		}
	case 79:
		if value, ok := v.AsDirectForwardingPathAvailability(); ok {
			return value, true
		}
	case 125:
		if value, ok := v.AsSRVCCHOIndication(); ok {
			return value, true
		}
	case 104:
		if value, ok := v.AsSourceToTargetTransparentContainer(); ok {
			return value, true
		}
	case 138:
		if value, ok := v.AsSourceToTargetTransparentContainerSecondary(); ok {
			return value, true
		}
	case 132:
		if value, ok := v.AsMSClassmark2(); ok {
			return value, true
		}
	case 133:
		if value, ok := v.AsMSClassmark3(); ok {
			return value, true
		}
	case 127:
		if value, ok := v.AsCSGId(); ok {
			return value, true
		}
	case 145:
		if value, ok := v.AsCellAccessMode(); ok {
			return value, true
		}
	case 150:
		if value, ok := v.AsPSServiceNotAvailable(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MMEDirectInformationTransferIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 122:
		if value, ok := v.AsInterSystemInformationTransferTypeMDT(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *TAIItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 47:
		if value, ok := v.AsTAIItem(); ok {
			return value, true
		}
	}
	return nil, false
}
