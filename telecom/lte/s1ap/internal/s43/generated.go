// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s43 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s43

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
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
func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainer(v *HandoverRequiredIEContainer, s *aper.SemanticCapture) {
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
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(v *HandoverRequiredIEContainer, s *aper.SemanticComparison) {
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
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(&(*v)[i], s)
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
func BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.TargeteNBIDExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.TargeteNBIDExtIEsExtContainer, s *aper.SemanticComparison) {
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
func BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s13.TimeBasedHandoverInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s13.TimeBasedHandoverInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs}} of TS 36.413: a list of SourceeNBToTargeteNBTransparentContainerExtIEsExtField values.
type SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer []SourceeNBToTargeteNBTransparentContainerExtIEsExtField

// SourceeNBToTargeteNBTransparentContainerExtIEsExtField is ProtocolExtensionField {{SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs}} of TS 36.413: an extension field.
type SourceeNBToTargeteNBTransparentContainerExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue SourceeNBToTargeteNBTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsExtField) WithoutReplay() SourceeNBToTargeteNBTransparentContainerExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}
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
	var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding binds AdditionalRRMPriorityIndex to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) New(value s00.AdditionalRRMPriorityIndex,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding binds ContextatSource to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding struct {
	info   s00.ExtensionInfo
	codec  s23.ContextatSourceValueCodec
	inject func(s23.ContextatSource,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s23.ContextatSource,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Codec() s23.ContextatSourceValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) New(value s23.ContextatSource,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeContextatSourceValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s23.ContextatSource,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding binds EmergencyIndicator to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.EmergencyIndicatorValueCodec
	inject func(s00.EmergencyIndicator,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.EmergencyIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) Codec() s00.EmergencyIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) New(value s00.EmergencyIndicator,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEmergencyIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.EmergencyIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding binds ENBUES1APID to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) New(value s00.ENBUES1APID,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding binds DirectForwardingPathAvailability to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding struct {
	info   s00.ExtensionInfo
	codec  s00.DirectForwardingPathAvailabilityValueCodec
	inject func(s00.DirectForwardingPathAvailability,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.DirectForwardingPathAvailability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Codec() s00.DirectForwardingPathAvailabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) New(value s00.DirectForwardingPathAvailability,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.DirectForwardingPathAvailability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

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
	codec  s01.HandoverTypeValueCodec
	inject func(s00.HandoverType,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.HandoverType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredHandoverTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredHandoverTypeIEBinding) Codec() s01.HandoverTypeValueCodec { return b.codec }

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
	if _, err := (*s01.BridgeHandoverTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequiredCauseIEBinding) New(value s17.Cause,

) (HandoverRequiredIEField, error) {
	if b.inject == nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRequiredIEField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequiredIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequiredCauseIEBinding) Get(field *HandoverRequiredIEField) (*s17.Cause,

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
	codec  s02.SRVCCHOIndicationValueCodec
	inject func(s00.SRVCCHOIndication,

	) HandoverRequiredIEValue

	get func(*HandoverRequiredIEValue,

	) (*s00.SRVCCHOIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequiredSRVCCHOIndicationIEBinding) Codec() s02.SRVCCHOIndicationValueCodec {
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
	if _, err := (*s02.BridgeSRVCCHOIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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
	codec  s02.SourceToTargetTransparentContainerValueCodec
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
func (b HandoverRequiredSourceToTargetTransparentContainerIEBinding) Codec() s02.SourceToTargetTransparentContainerValueCodec {
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
	if _, err := (*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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

// HandoverRequiredValueCodec is the concrete ValueCodec[HandoverRequired].
type HandoverRequiredValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequired,

		error)
	encode func(HandoverRequired,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequired, aper.DecodeState,

	) (HandoverRequired, aper.Snapshot,

	)
	compare func(HandoverRequired, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequiredValueCodec) New(value HandoverRequired,

) (HandoverRequiredAPERValue, error) {
	if c.encode == nil {
		return HandoverRequiredAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequiredAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequiredAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequiredAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequiredValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequiredAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequiredAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequiredAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequiredAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequiredAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequiredValueCodec) EncodeAPER(value HandoverRequiredAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRequiredValueCodec) encodeBudgetValue(value HandoverRequired,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequiredValueCodec) encodeChanged(value HandoverRequired,

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

// TargetRNCIDValueCodec is the concrete ValueCodec[TargetRNCID].
type TargetRNCIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s42.TargetRNCID,

		error)
	encode func(s42.TargetRNCID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s42.TargetRNCID, aper.DecodeState,

	) (s42.TargetRNCID, aper.Snapshot,

	)
	compare func(s42.TargetRNCID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCIDValueCodec) New(value s42.TargetRNCID,

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
func (c TargetRNCIDValueCodec) encodeBudgetValue(value s42.TargetRNCID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCIDValueCodec) encodeChanged(value s42.TargetRNCID,

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
func BridgeHandoverRequiredIEValueValidateS1APIEContainer(fields HandoverRequiredIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields ENBDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields MMEDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeTargetRNCIDExtIEsValueValidateS1APExtensionContainer(fields s13.TargetRNCIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.TargetRNCIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.TargetRNCIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargetRNCIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTargeteNBIDExtIEsValueValidateS1APExtensionContainer(fields s13.TargeteNBIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.TargeteNBIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s13.TargeteNBIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargeteNBIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ENBDirectInformationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueERABIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) ENBDirectInformationTransferIEValueERABIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{path: "ENBDirectInformationTransferIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueERABIEContainerList, error) {
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

// HandoverRequiredIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueERABIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEValueERABIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequiredIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return HandoverRequiredIEValueERABIEContainerListValueCodec{path: "HandoverRequiredIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequiredIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequiredIEField
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
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value HandoverRequiredIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequiredIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequiredIEValueERABIEContainerList, options aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v HandoverRequiredIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APERABIEContainerList(&v, &s)
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
	return MMEDirectInformationTransferIEValueERABIEContainerListValueCodec{path: "MMEDirectInformationTransferIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueERABIEContainerList, error) {
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

// TargeteNBIDExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TargeteNB-ID-ExtIEs}} codec of TS 36.413.
func TargeteNBIDExtIEsValueExtensionFieldTableCodec(table s00.TargeteNBIDExtIEsValueExtensionTable) s13.TargeteNBIDExtIEsExtFieldValueCodec {
	if !*s00.BridgeTargeteNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.TargeteNBIDExtIEsExtFieldValueCodec{}
	}
	return func() s13.TargeteNBIDExtIEsExtFieldValueCodec {
		sealed := s13.TargeteNBIDExtIEsExtFieldValueCodec{}
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldPath(&sealed) = "TargeteNBIDExtIEsExtField"
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.TargeteNBIDExtIEsExtField, error) {
			var field s13.TargeteNBIDExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TargeteNBIDExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TargeteNBIDExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.TargeteNBIDExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.TargeteNBIDExtIEsExtField, options aper.DecodeState) (s13.TargeteNBIDExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.TargeteNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TimeBasedHandoverInformation-ExtIEs}} codec of TS 36.413.
func TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec(table s00.TimeBasedHandoverInformationExtIEsValueExtensionTable) s13.TimeBasedHandoverInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeTimeBasedHandoverInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s13.TimeBasedHandoverInformationExtIEsExtFieldValueCodec{}
	}
	return func() s13.TimeBasedHandoverInformationExtIEsExtFieldValueCodec {
		sealed := s13.TimeBasedHandoverInformationExtIEsExtFieldValueCodec{}
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "TimeBasedHandoverInformationExtIEsExtField"
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.TimeBasedHandoverInformationExtIEsExtField, error) {
			var field s13.TimeBasedHandoverInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeBasedHandoverInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtField")
			}
			return field, nil
		}
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s13.TimeBasedHandoverInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s13.TimeBasedHandoverInformationExtIEsExtField, options aper.DecodeState) (s13.TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s13.TimeBasedHandoverInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TargetRNCIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargetRNC-ID-ExtIEs}} codec of TS 36.413.
func TargetRNCIDExtIEsValueExtensionTableCodec(table s00.TargetRNCIDExtIEsValueExtensionTable, bounds aper.ListBounds) s13.TargetRNCIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargetRNCIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.TargetRNCIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.TargetRNCIDExtIEsExtContainerValueCodec {
		sealed := s13.TargetRNCIDExtIEsExtContainerValueCodec{}
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "TargetRNCIDExtIEsExtContainer"
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.TargetRNCIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.TargetRNCIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.TargetRNCIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.TargetRNCIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeTargetRNCIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.TargetRNCIDExtIEsExtContainer, options aper.DecodeState) (s13.TargetRNCIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s42.BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.TargetRNCIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s42.BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TargeteNBIDExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TargeteNB-ID-ExtIEs}} codec of TS 36.413.
func TargeteNBIDExtIEsValueExtensionTableCodec(table s00.TargeteNBIDExtIEsValueExtensionTable, bounds aper.ListBounds) s13.TargeteNBIDExtIEsExtContainerValueCodec {
	if !*s00.BridgeTargeteNBIDExtIEsValueExtensionTableFieldBound(&table) {
		return s13.TargeteNBIDExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s13.TargeteNBIDExtIEsExtContainerValueCodec {
		sealed := s13.TargeteNBIDExtIEsExtContainerValueCodec{}
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldPath(&sealed) = "TargeteNBIDExtIEsExtContainer"
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.TargeteNBIDExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s13.TargeteNBIDExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s13.TargeteNBIDExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s13.TargeteNBIDExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s13.TargeteNBIDExtIEsExtContainer, options aper.DecodeState) (s13.TargeteNBIDExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s13.TargeteNBIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s13.BridgeTargeteNBIDExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return ENBDirectInformationTransferIEFieldValueCodec{path: "ENBDirectInformationTransferIEField", decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEField, error) {
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

// HandoverRequiredIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueIEFieldTableCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEFieldValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return HandoverRequiredIEFieldValueCodec{}
	}
	return HandoverRequiredIEFieldValueCodec{path: "HandoverRequiredIEField", decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEField, error) {
		var field HandoverRequiredIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "HandoverRequiredIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "HandoverRequiredIEField")
		}
		return field, nil
	}, encode: func(field HandoverRequiredIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v HandoverRequiredIEField, options aper.DecodeState) (HandoverRequiredIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequiredIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(&v, &s)
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
	return MMEDirectInformationTransferIEFieldValueCodec{path: "MMEDirectInformationTransferIEField", decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEField, error) {
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

// ENBDirectInformationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueIETableCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) ENBDirectInformationTransferIEContainerValueCodec {
	if !*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&table) {
		return ENBDirectInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEContainerValueCodec{path: "ENBDirectInformationTransferIEContainer", decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEContainer, error) {
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

// HandoverRequiredIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueIETableCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) HandoverRequiredIEContainerValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return HandoverRequiredIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverRequiredIEContainerValueCodec{path: "HandoverRequiredIEContainer", decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequiredIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequiredIEField
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
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEContainer")
		}
		return fields, nil
	},
		encode: func(fields HandoverRequiredIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v HandoverRequiredIEContainer, options aper.DecodeState) (HandoverRequiredIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v HandoverRequiredIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(&v, &s)
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
	return MMEDirectInformationTransferIEContainerValueCodec{path: "MMEDirectInformationTransferIEContainer", decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEContainer, error) {
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

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBDirectInformationTransferIEs}} codec of TS 36.413.
func ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{path: "ENBDirectInformationTransferIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
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

// HandoverRequiredIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueProtocolErrorIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{path: "HandoverRequiredIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequiredIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequiredIEField
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
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value HandoverRequiredIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequiredIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequiredIEValueProtocolErrorIEContainerList, options aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequiredIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APProtocolErrorIEContainerList(
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
	return MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{path: "MMEDirectInformationTransferIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
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

// ENBDirectInformationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBDirectInformationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBDirectInformationTransferIEValueProtocolIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{path: "ENBDirectInformationTransferIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBDirectInformationTransferIEValueProtocolIEContainerList, error) {
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

// HandoverRequiredIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverRequiredIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverRequiredIEValueProtocolIEContainerListCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) HandoverRequiredIEValueProtocolIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return HandoverRequiredIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return HandoverRequiredIEValueProtocolIEContainerListValueCodec{path: "HandoverRequiredIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequiredIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequiredIEField
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
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "HandoverRequiredIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value HandoverRequiredIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequiredIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequiredIEValueProtocolIEContainerList, options aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequiredIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
	return MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec{path: "MMEDirectInformationTransferIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (MMEDirectInformationTransferIEValueProtocolIEContainerList, error) {
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// handoverRequiredIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverRequiredIEValue].
type HandoverRequiredIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) HandoverRequiredIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (HandoverRequiredIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(v *HandoverRequiredIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(v *HandoverRequiredIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// targetRNCIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargetRNCIDExtIEsValue].
type TargetRNCIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.TargetRNCIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.TargetRNCIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// targeteNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargeteNBIDExtIEsValue].
type TargeteNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.TargeteNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.TargeteNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTargeteNBIDExtIEsValueCaptureS1APProtocolExtensionField(v *s13.TargeteNBIDExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeTargeteNBIDExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeTargeteNBIDExtIEsExtFieldFieldReplay(v), *s13.BridgeTargeteNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(v *s13.TargeteNBIDExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeTargeteNBIDExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeTargeteNBIDExtIEsExtFieldFieldReplay(v), *s13.BridgeTargeteNBIDExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s13.TimeBasedHandoverInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldReplay(v), *s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(v *s13.TimeBasedHandoverInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeTimeBasedHandoverInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldReplay(v), *s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldWithoutReplay(v))
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

// HandoverRequiredAPERValue is the concrete APERValue[HandoverRequired].
type HandoverRequiredAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverRequired

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequiredAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequiredAPERValue) WithoutReplay() HandoverRequiredAPERValue {
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

// TargetRNCIDAPERValue is the concrete APERValue[TargetRNCID].
type TargetRNCIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s42.TargetRNCID

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
func BridgeTargetRNCIDExtIEsValueValidateS1APIEContainer(fields s13.TargetRNCIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeTargetRNCIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeTargetRNCIDExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeTargetRNCIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTargeteNBIDExtIEsValueValidateS1APIEContainer(fields s13.TargeteNBIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeTargeteNBIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeTargeteNBIDExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeTargeteNBIDExtIEsValueMethodRule(field.Value).Assignment
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

func BridgeHandoverRequiredIEValueCaptureS1APERABIEContainerList(v *HandoverRequiredIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APERABIEContainerList(v *HandoverRequiredIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverRequiredIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer].
type SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, error)
	encode  func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.Snapshot)
	compare func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) New(value SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) EncodeAPER(value SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) encodeBudgetValue(value SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) encodeChanged(value SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

func BridgeHandoverRequiredIEValueCaptureS1APProtocolErrorIEContainerList(v *HandoverRequiredIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolErrorIEContainerList(v *HandoverRequiredIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverRequiredIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainerList(v *HandoverRequiredIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainerList(v *HandoverRequiredIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeHandoverRequiredIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

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

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIESingleContainer(v *HandoverRequiredIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIESingleContainer(v *HandoverRequiredIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

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

// SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[SourceeNBToTargeteNBTransparentContainerExtIEsExtField].
type SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceeNBToTargeteNBTransparentContainerExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) WithoutReplay() SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer].
type SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) WithoutReplay() SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue {
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
func BridgeCaptureS1APHandoverRequired(v *HandoverRequired, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverRequired(v *HandoverRequired, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
					s08.BridgeCompareS1APSRVCCHOIndication(v.rowSRVCCHOIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(104):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainer == nil)
				if v.rowSourceToTargetTransparentContainer != nil {
					s08.BridgeCompareS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(138):
			{
				f := s.Begin()
				s.Bool(v.rowSourceToTargetTransparentContainerSecondary == nil)
				if v.rowSourceToTargetTransparentContainerSecondary != nil {
					s08.BridgeCompareS1APSourceToTargetTransparentContainer(v.rowSourceToTargetTransparentContainerSecondary, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
			s42.BridgeCaptureS1APRIMRoutingAddress(v.RIMRoutingAddress, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s16.BridgeRIMTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRIMTransfer(v *RIMTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s08.BridgeCompareS1APRIMInformation(&v.RIMInformation, s)
	{
		f := s.Begin()
		s.Bool(v.RIMRoutingAddress == nil)
		if v.RIMRoutingAddress != nil {
			s42.BridgeCompareS1APRIMRoutingAddress(v.RIMRoutingAddress, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s16.BridgeRIMTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSourceeNBToTargeteNBTransparentContainerExtIEsValue(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(175):
			{
				f := s.Begin()
				s.Bool(v.rowMobilityInformation == nil)
				if v.rowMobilityInformation != nil {
					s00.BridgeCaptureS1APS1APIEsMobilityInformation(v.rowMobilityInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(194):
			{
				f := s.Begin()
				s.Bool(v.rowUEHistoryInformationFromTheUE == nil)
				if v.rowUEHistoryInformationFromTheUE != nil {
					s00.BridgeCaptureS1APUEHistoryInformationFromTheUE(v.rowUEHistoryInformationFromTheUE, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(296):
			{
				f := s.Begin()
				s.Bool(v.rowIMSvoiceEPSfallbackfrom5G == nil)
				if v.rowIMSvoiceEPSfallbackfrom5G != nil {
					s00.BridgeCaptureS1APIMSvoiceEPSfallbackfrom5G(v.rowIMSvoiceEPSfallbackfrom5G, s)
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
		case s00.ProtocolIEID(300):
			{
				f := s.Begin()
				s.Bool(v.rowContextatSource == nil)
				if v.rowContextatSource != nil {
					s23.BridgeCaptureS1APContextatSource(v.rowContextatSource, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(311):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemMeasurementConfiguration == nil)
				if v.rowIntersystemMeasurementConfiguration != nil {
					s28.BridgeCaptureS1APIntersystemMeasurementConfiguration(v.rowIntersystemMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(312):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeID == nil)
				if v.rowSourceNodeID != nil {
					s39.BridgeCaptureS1APSourceNodeID(v.rowSourceNodeID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(326):
			{
				f := s.Begin()
				s.Bool(v.rowEmergencyIndicator == nil)
				if v.rowEmergencyIndicator != nil {
					s00.BridgeCaptureS1APEmergencyIndicator(v.rowEmergencyIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(337):
			{
				f := s.Begin()
				s.Bool(v.rowUEContextReferenceatSourceeNB == nil)
				if v.rowUEContextReferenceatSourceeNB != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowUEContextReferenceatSourceeNB, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(343):
			{
				f := s.Begin()
				s.Bool(v.rowSourceSNID == nil)
				if v.rowSourceSNID != nil {
					s23.BridgeCaptureS1APGlobalRANNODEID(v.rowSourceSNID, s)
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
		case s00.ProtocolIEID(350):
			{
				f := s.Begin()
				s.Bool(v.rowTimeBasedHandoverInformation == nil)
				if v.rowTimeBasedHandoverInformation != nil {
					BridgeCaptureS1APTimeBasedHandoverInformation(v.rowTimeBasedHandoverInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) captureSemantics(s aper.SemanticCapture) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	BridgeCaptureS1APSourceeNBToTargeteNBTransparentContainerExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APSourceeNBToTargeteNBTransparentContainerExtIEsValue(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(175):
			{
				f := s.Begin()
				s.Bool(v.rowMobilityInformation == nil)
				if v.rowMobilityInformation != nil {
					s08.BridgeCompareS1APS1APIEsMobilityInformation(v.rowMobilityInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(194):
			{
				f := s.Begin()
				s.Bool(v.rowUEHistoryInformationFromTheUE == nil)
				if v.rowUEHistoryInformationFromTheUE != nil {
					s08.BridgeCompareS1APUEHistoryInformationFromTheUE(v.rowUEHistoryInformationFromTheUE, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(296):
			{
				f := s.Begin()
				s.Bool(v.rowIMSvoiceEPSfallbackfrom5G == nil)
				if v.rowIMSvoiceEPSfallbackfrom5G != nil {
					s02.BridgeCompareS1APIMSvoiceEPSfallbackfrom5G(v.rowIMSvoiceEPSfallbackfrom5G, s)
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
		case s00.ProtocolIEID(300):
			{
				f := s.Begin()
				s.Bool(v.rowContextatSource == nil)
				if v.rowContextatSource != nil {
					s23.BridgeCompareS1APContextatSource(v.rowContextatSource, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(311):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemMeasurementConfiguration == nil)
				if v.rowIntersystemMeasurementConfiguration != nil {
					s28.BridgeCompareS1APIntersystemMeasurementConfiguration(v.rowIntersystemMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(312):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeID == nil)
				if v.rowSourceNodeID != nil {
					s39.BridgeCompareS1APSourceNodeID(v.rowSourceNodeID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(326):
			{
				f := s.Begin()
				s.Bool(v.rowEmergencyIndicator == nil)
				if v.rowEmergencyIndicator != nil {
					s02.BridgeCompareS1APEmergencyIndicator(v.rowEmergencyIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(337):
			{
				f := s.Begin()
				s.Bool(v.rowUEContextReferenceatSourceeNB == nil)
				if v.rowUEContextReferenceatSourceeNB != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowUEContextReferenceatSourceeNB, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(343):
			{
				f := s.Begin()
				s.Bool(v.rowSourceSNID == nil)
				if v.rowSourceSNID != nil {
					s23.BridgeCompareS1APGlobalRANNODEID(v.rowSourceSNID, s)
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
		case s00.ProtocolIEID(350):
			{
				f := s.Begin()
				s.Bool(v.rowTimeBasedHandoverInformation == nil)
				if v.rowTimeBasedHandoverInformation != nil {
					BridgeCompareS1APTimeBasedHandoverInformation(v.rowTimeBasedHandoverInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSourceeNBToTargeteNBTransparentContainerExtIEsValue(&v, &s)
	return s
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
				s42.BridgeCaptureS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, nil, false)
		}
	case s00.TargetIDChoiceCGI:
		{
			f := s.Begin()
			s.Bool(v.CGI == nil)
			if v.CGI != nil {
				s16.BridgeCaptureS1APCGI(v.CGI, s)
			}
			s.End(f, nil, false)
		}
	case s00.TargetIDChoiceTargetgNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.TargetgNgRanNodeID == nil)
			if v.TargetgNgRanNodeID != nil {
				s42.BridgeCaptureS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
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
				s42.BridgeCompareS1APTargetRNCID(v.TargetRNCID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.TargetIDChoiceCGI:
		{
			f := s.Begin()
			s.Bool(v.CGI == nil)
			if v.CGI != nil {
				s16.BridgeCompareS1APCGI(v.CGI, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.TargetIDChoiceTargetgNgRanNodeID:
		{
			f := s.Begin()
			s.Bool(v.TargetgNgRanNodeID == nil)
			if v.TargetgNgRanNodeID != nil {
				s42.BridgeCompareS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 3 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCaptureS1APTargeteNBID(v *TargeteNBID, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APGlobalENBID(&v.GlobalENBID, s)
	s40.BridgeCaptureS1APTAI(&v.SelectedTAI, s)
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
	s21.BridgeCompareS1APGlobalENBID(&v.GlobalENBID, s)
	s40.BridgeCompareS1APTAI(&v.SelectedTAI, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTimeBasedHandoverInformation(v *TimeBasedHandoverInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APHandoverWindowStart(&v.HOWindowStart, s)
	s00.BridgeCaptureS1APHandoverWindowDuration(&v.HOWindowDuration, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTimeBasedHandoverInformation(v *TimeBasedHandoverInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APHandoverWindowStart(&v.HOWindowStart, s)
	s02.BridgeCompareS1APHandoverWindowDuration(&v.HOWindowDuration, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
	RIMRoutingAddress *s42.RIMRoutingAddress            `asn1:"tag:1,context,explicit,optional" json:"RIMRoutingAddress,omitempty"`
	IEExtensions      s12.RIMTransferExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NewRIMRoutingAddressGERANCellID creates a RIMRoutingAddress with the gERAN-Cell-ID alternative.
func BridgeNewRIMRoutingAddressGERANCellIDLegacy(v s22.GERANCellID) s42.RIMRoutingAddress {
	return s42.RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceGERANCellID,
		GERANCellID: &v,
	}
}

// NewRIMRoutingAddressTargetRNCID creates a RIMRoutingAddress with the targetRNC-ID alternative.
func BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v s42.TargetRNCID) s42.RIMRoutingAddress {
	return s42.RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewRIMRoutingAddressEHRPDSectorID creates a RIMRoutingAddress with the eHRPD-Sector-ID alternative.
func BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v []byte) s42.RIMRoutingAddress {
	return s42.RIMRoutingAddress{
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
	perPadding         aper.CompletePadding   `json:"-"`
	perOpenTypePadding aper.CompletePadding   `json:"-"`
	UnknownExtension   *aper.ChoiceExtension  `json:"UnknownExtension,omitempty"`
	TargeteNBID        *TargeteNBID           `json:"TargeteNBID,omitempty"`
	TargetRNCID        *s42.TargetRNCID       `json:"TargetRNCID,omitempty"`
	CGI                *s16.CGI               `json:"CGI,omitempty"`
	TargetgNgRanNodeID *s42.TargetNgRanNodeID `json:"TargetgNgRanNodeID,omitempty"`
}

// NewTargetIDTargeteNBID creates a TargetID with the targeteNB-ID alternative.
func BridgeNewTargetIDTargeteNBIDLegacy(v TargeteNBID) TargetID {
	return TargetID{
		Choice:      s00.TargetIDChoiceTargeteNBID,
		TargeteNBID: &v,
	}
}

// NewTargetIDTargetRNCID creates a TargetID with the targetRNC-ID alternative.
func BridgeNewTargetIDTargetRNCIDLegacy(v s42.TargetRNCID) TargetID {
	return TargetID{
		Choice:      s00.TargetIDChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewTargetIDCGI creates a TargetID with the cGI alternative.
func BridgeNewTargetIDCGILegacy(v s16.CGI) TargetID {
	return TargetID{
		Choice: s00.TargetIDChoiceCGI,
		CGI:    &v,
	}
}

// NewTargetIDTargetgNgRanNodeID creates a TargetID with the targetgNgRanNode-ID alternative.
func BridgeNewTargetIDTargetgNgRanNodeIDLegacy(v s42.TargetNgRanNodeID) TargetID {
	return TargetID{
		Choice:             s00.TargetIDChoiceTargetgNgRanNodeID,
		TargetgNgRanNodeID: &v,
	}
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
	GlobalENBID       s21.GlobalENBID                   `asn1:"tag:0,context,implicit"`
	SelectedTAI       s40.TAI                           `asn1:"tag:1,context,implicit"`
	IEExtensions      s13.TargeteNBIDExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                              `asn1:"-" json:"-"`
	extCount          int64                             `asn1:"-" json:"-"`
	extPresent        []bool                            `asn1:"-" json:"-"`
	extData           [][]byte                          `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TimeBasedHandoverInformation represents the ASN.1 type TimeBasedHandoverInformation (SEQUENCE).
type TimeBasedHandoverInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	HOWindowStart     s00.HandoverWindowStart                            `asn1:"tag:0,context,implicit"`
	HOWindowDuration  s00.HandoverWindowDuration                         `asn1:"tag:1,context,implicit"`
	IEExtensions      s13.TimeBasedHandoverInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
		if err := s42.BridgeRIMRoutingAddressMethodMarshalAPERTo(v.RIMRoutingAddress, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s12.BridgeRIMTransferExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RIMTransfer from APER format.
func (v *RIMTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *RIMTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RIMTransfer{}
	var extAdditions aper.ExtensionAdditions
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
		var dec_rimroutingaddress s42.RIMRoutingAddress
		if err := s42.BridgeRIMRoutingAddressMethodUnmarshalAPERFrom(&dec_rimroutingaddress, bb); err != nil {
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
		tmp_ieextensions := make(s12.RIMTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.RIMTransferExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s42.BridgeTargetNgRanNodeIDMethodMarshalAPERTo(v.TargetgNgRanNodeID, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding targetgNgRanNode-ID: %w", err)
			}
		default:
			return fmt.Errorf("unknown TargetID extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s08.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
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
		if err := s42.BridgeTargetRNCIDMethodMarshalAPERTo(v.TargetRNCID, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding targetRNC-ID: %w", err)
		}
	case s00.TargetIDChoiceCGI:
		if v.CGI == nil {
			return fmt.Errorf("choice alternative cGI is nil")
		}
		if err := s16.BridgeCGIMethodMarshalAPERTo(v.CGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			var dec_targetgngrannodeid s42.TargetNgRanNodeID
			if err := s42.BridgeTargetNgRanNodeIDMethodUnmarshalAPERFrom(&dec_targetgngrannodeid, inner); err != nil {
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
		var dec_targetrncid s42.TargetRNCID
		if err := s42.BridgeTargetRNCIDMethodUnmarshalAPERFrom(&dec_targetrncid, bb); err != nil {
			return runtime.WrapDecodePath(err, "TargetRNCID")
		}
		if err := aper.ChargeValue(bb, dec_targetrncid); err != nil {
			return err
		}
		v.TargetRNCID = &dec_targetrncid
		bb.LeaveComponent(toleranceMark_targetrncid)
	case s00.TargetIDChoiceCGI:
		toleranceMark_cgi := bb.EnterComponent("CGI")
		var dec_cgi s16.CGI
		if err := s16.BridgeCGIMethodUnmarshalAPERFrom(&dec_cgi, bb); err != nil {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s21.BridgeGlobalENBIDMethodMarshalAPERTo(&v.GlobalENBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding global-ENB-ID: %w", err)
	}
	if err := s40.BridgeTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding selected-TAI: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TargeteNBID from APER format.
func (v *TargeteNBID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *TargeteNBID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TargeteNBID{}
	var extAdditions aper.ExtensionAdditions
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
	if err := s21.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&v.GlobalENBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "GlobalENBID")
	}
	bb.LeaveComponent(toleranceMark_globalenbid)
	toleranceMark_selectedtai := bb.EnterComponent("SelectedTAI")
	if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TargeteNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TargeteNBIDExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TimeBasedHandoverInformation to APER format.
func (v *TimeBasedHandoverInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TimeBasedHandoverInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HOWindowStart), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false); err != nil {
		return fmt.Errorf("encoding hOWindowStart: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HOWindowDuration), s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(6000), false); err != nil {
		return fmt.Errorf("encoding hOWindowDuration: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TimeBasedHandoverInformation from APER format.
func (v *TimeBasedHandoverInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TimeBasedHandoverInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	bb.EnterComponent("TimeBasedHandoverInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TimeBasedHandoverInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *TimeBasedHandoverInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeBasedHandoverInformation{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_howindowstart, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(1048575), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HOWindowStart")
	}
	v.HOWindowStart = s00.HandoverWindowStart(val_howindowstart)
	val_howindowduration, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(1), s08.BridgeInt64Ptr(6000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HOWindowDuration")
	}
	v.HOWindowDuration = s00.HandoverWindowDuration(val_howindowduration)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s13.TimeBasedHandoverInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s13.TimeBasedHandoverInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s13.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RIMTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "RIMTransfer", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargetID", v.receivedLocation, v.perPadding)
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
func (v *TargeteNBID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TargeteNBID", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TimeBasedHandoverInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TimeBasedHandoverInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TimeBasedHandoverInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TimeBasedHandoverInformation) WithoutReplay() TimeBasedHandoverInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TimeBasedHandoverInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
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

// Extensions returns owned unknown sequence additions.
func (v *TimeBasedHandoverInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TimeBasedHandoverInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TimeBasedHandoverInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TimeBasedHandoverInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TimeBasedHandoverInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TimeBasedHandoverInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TimeBasedHandoverInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TimeBasedHandoverInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TimeBasedHandoverInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TimeBasedHandoverInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TimeBasedHandoverInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTimeBasedHandoverInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TimeBasedHandoverInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TimeBasedHandoverInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TimeBasedHandoverInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TimeBasedHandoverInformation")
}
func (v *TimeBasedHandoverInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TimeBasedHandoverInformation")
}
func (v *TimeBasedHandoverInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTimeBasedHandoverInformation(v, &s)
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
func (v *TimeBasedHandoverInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TimeBasedHandoverInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TimeBasedHandoverInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TimeBasedHandoverInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TimeBasedHandoverInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTimeBasedHandoverInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TimeBasedHandoverInformation{}
		return report, aper.OperationError(err, "TimeBasedHandoverInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TimeBasedHandoverInformation")
}

// NewRIMRoutingAddressGERANCellID constructs a checked complete value.
func NewRIMRoutingAddressGERANCellID(v s22.GERANCellID, options ...aper.BuildOption) (s42.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	value := BridgeNewRIMRoutingAddressGERANCellIDLegacy(v)
	if _, err := s42.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressGERANCellID")
}

// NewRIMRoutingAddressTargetRNCID constructs a checked complete value.
func NewRIMRoutingAddressTargetRNCID(v s42.TargetRNCID, options ...aper.BuildOption) (s42.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	value := BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v)
	if _, err := s42.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressTargetRNCID")
}

// NewRIMRoutingAddressEHRPDSectorID constructs a checked complete value.
func NewRIMRoutingAddressEHRPDSectorID(v []byte, options ...aper.BuildOption) (s42.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	value := BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v)
	if _, err := s42.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s42.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressEHRPDSectorID")
}

// NewTargetIDTargeteNBID constructs a checked complete value.
func NewTargetIDTargeteNBID(v TargeteNBID, options ...aper.BuildOption) (TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	value := BridgeNewTargetIDTargeteNBIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	return value, aper.OperationError(nil, "TargetIDTargeteNBID")
}

// NewTargetIDTargetRNCID constructs a checked complete value.
func NewTargetIDTargetRNCID(v s42.TargetRNCID, options ...aper.BuildOption) (TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	value := BridgeNewTargetIDTargetRNCIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	return value, aper.OperationError(nil, "TargetIDTargetRNCID")
}

// NewTargetIDCGI constructs a checked complete value.
func NewTargetIDCGI(v s16.CGI, options ...aper.BuildOption) (TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	value := BridgeNewTargetIDCGILegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	return value, aper.OperationError(nil, "TargetIDCGI")
}

// NewTargetIDTargetgNgRanNodeID constructs a checked complete value.
func NewTargetIDTargetgNgRanNodeID(v s42.TargetNgRanNodeID, options ...aper.BuildOption) (TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	value := BridgeNewTargetIDTargetgNgRanNodeIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	return value, aper.OperationError(nil, "TargetIDTargetgNgRanNodeID")
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

// HandoverRequired represents the ASN.1 type HandoverRequired (SEQUENCE).
type HandoverRequired struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      HandoverRequiredIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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

// MarshalAPER encodes HandoverRequired to APER format.
func (v *HandoverRequired) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverRequired) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes HandoverRequired from APER format.
func (v *HandoverRequired) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *HandoverRequired) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	bb.EnterComponent("HandoverRequired")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRequired")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	v.perPadding = padding
	return nil
}
func (v *HandoverRequired) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequired{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(HandoverRequiredIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem HandoverRequiredIEField
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

// UnmarshalAPER decodes ENBDirectInformationTransfer from APER format.
func (v *ENBDirectInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENBDirectInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBDirectInformationTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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

// UnmarshalAPER decodes MMEDirectInformationTransfer from APER format.
func (v *MMEDirectInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *MMEDirectInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEDirectInformationTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(MMEDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
func (v *ENBDirectInformationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBDirectInformationTransfer", v.receivedLocation, v.perPadding)
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
func (v *HandoverRequired) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverRequired", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverRequired", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverRequired) WithoutReplay() HandoverRequired {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverRequired
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterSystemInformationTransferType", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEDirectInformationTransfer", v.receivedLocation, v.perPadding)
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
func (v *HandoverRequired) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverRequired) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequired.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequired.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverRequired) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequired.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequired.Extensions[%d]", index))
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
func (v *HandoverRequired) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverRequired")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverRequired) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverRequired")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverRequired(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverRequired")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverRequired")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverRequired) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverRequired")
}
func (v *HandoverRequired) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverRequired")
}
func (v *HandoverRequired) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverRequired(v, &s)
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
func (v *HandoverRequired) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverRequired) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *HandoverRequired) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverRequired")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverRequired
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverRequired(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverRequired{}
		return report, aper.OperationError(err, "HandoverRequired")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverRequired")
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

type SourceeNBToTargeteNBTransparentContainerExtIEsValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowMobilityInformation                 *s00.S1APIEsMobilityInformation
	rowUEHistoryInformationFromTheUE       *s00.UEHistoryInformationFromTheUE
	rowIMSvoiceEPSfallbackfrom5G           *s00.IMSvoiceEPSfallbackfrom5G
	rowAdditionalRRMPriorityIndex          *s00.AdditionalRRMPriorityIndex
	rowContextatSource                     *s23.ContextatSource
	rowIntersystemMeasurementConfiguration *s28.IntersystemMeasurementConfiguration
	rowSourceNodeID                        *s39.SourceNodeID
	rowEmergencyIndicator                  *s00.EmergencyIndicator
	rowUEContextReferenceatSourceeNB       *s00.ENBUES1APID
	rowSourceSNID                          *s23.GlobalRANNODEID
	rowDirectForwardingPathAvailability    *s00.DirectForwardingPathAvailability
	rowTimeBasedHandoverInformation        *TimeBasedHandoverInformation
}

func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(175):
		return v.rowMobilityInformation != nil
	case s00.ProtocolIEID(194):
		return v.rowUEHistoryInformationFromTheUE != nil
	case s00.ProtocolIEID(296):
		return v.rowIMSvoiceEPSfallbackfrom5G != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(300):
		return v.rowContextatSource != nil
	case s00.ProtocolIEID(311):
		return v.rowIntersystemMeasurementConfiguration != nil
	case s00.ProtocolIEID(312):
		return v.rowSourceNodeID != nil
	case s00.ProtocolIEID(326):
		return v.rowEmergencyIndicator != nil
	case s00.ProtocolIEID(337):
		return v.rowUEContextReferenceatSourceeNB != nil
	case s00.ProtocolIEID(343):
		return v.rowSourceSNID != nil
	case s00.ProtocolIEID(79):
		return v.rowDirectForwardingPathAvailability != nil
	case s00.ProtocolIEID(350):
		return v.rowTimeBasedHandoverInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether the opaque alternative is selected.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SourceeNBToTargeteNBTransparentContainerExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs"}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(175):
		return aper.UnknownSelector
	case s00.ProtocolIEID(194):
		return aper.UnknownSelector
	case s00.ProtocolIEID(296):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(300):
		return aper.UnknownSelector
	case s00.ProtocolIEID(311):
		return aper.UnknownSelector
	case s00.ProtocolIEID(312):
		return aper.UnknownSelector
	case s00.ProtocolIEID(326):
		return aper.UnknownSelector
	case s00.ProtocolIEID(337):
		return aper.UnknownSelector
	case s00.ProtocolIEID(343):
		return aper.UnknownSelector
	case s00.ProtocolIEID(79):
		return aper.UnknownSelector
	case s00.ProtocolIEID(350):
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
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
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
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
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

// AsMobilityInformation returns the selected MobilityInformation value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsMobilityInformation() (*s00.S1APIEsMobilityInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(175) || v.rowMobilityInformation == nil {
		return nil, false
	}
	return v.rowMobilityInformation, true
}

// AsUEHistoryInformationFromTheUE returns the selected UEHistoryInformationFromTheUE value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsUEHistoryInformationFromTheUE() (*s00.UEHistoryInformationFromTheUE, bool) {
	if v == nil || v.id != s00.ProtocolIEID(194) || v.rowUEHistoryInformationFromTheUE == nil {
		return nil, false
	}
	return v.rowUEHistoryInformationFromTheUE, true
}

// AsIMSvoiceEPSfallbackfrom5G returns the selected IMSvoiceEPSfallbackfrom5G value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsIMSvoiceEPSfallbackfrom5G() (*s00.IMSvoiceEPSfallbackfrom5G, bool) {
	if v == nil || v.id != s00.ProtocolIEID(296) || v.rowIMSvoiceEPSfallbackfrom5G == nil {
		return nil, false
	}
	return v.rowIMSvoiceEPSfallbackfrom5G, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsContextatSource returns the selected ContextatSource value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsContextatSource() (*s23.ContextatSource, bool) {
	if v == nil || v.id != s00.ProtocolIEID(300) || v.rowContextatSource == nil {
		return nil, false
	}
	return v.rowContextatSource, true
}

// AsIntersystemMeasurementConfiguration returns the selected IntersystemMeasurementConfiguration value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsIntersystemMeasurementConfiguration() (*s28.IntersystemMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(311) || v.rowIntersystemMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowIntersystemMeasurementConfiguration, true
}

// AsSourceNodeID returns the selected SourceNodeID value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsSourceNodeID() (*s39.SourceNodeID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(312) || v.rowSourceNodeID == nil {
		return nil, false
	}
	return v.rowSourceNodeID, true
}

// AsEmergencyIndicator returns the selected EmergencyIndicator value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsEmergencyIndicator() (*s00.EmergencyIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(326) || v.rowEmergencyIndicator == nil {
		return nil, false
	}
	return v.rowEmergencyIndicator, true
}

// AsUEContextReferenceatSourceeNB returns the selected UEContextReferenceatSourceeNB value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsUEContextReferenceatSourceeNB() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(337) || v.rowUEContextReferenceatSourceeNB == nil {
		return nil, false
	}
	return v.rowUEContextReferenceatSourceeNB, true
}

// AsSourceSNID returns the selected SourceSNID value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsSourceSNID() (*s23.GlobalRANNODEID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(343) || v.rowSourceSNID == nil {
		return nil, false
	}
	return v.rowSourceSNID, true
}

// AsDirectForwardingPathAvailability returns the selected DirectForwardingPathAvailability value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsDirectForwardingPathAvailability() (*s00.DirectForwardingPathAvailability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(79) || v.rowDirectForwardingPathAvailability == nil {
		return nil, false
	}
	return v.rowDirectForwardingPathAvailability, true
}

// AsTimeBasedHandoverInformation returns the selected TimeBasedHandoverInformation value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsTimeBasedHandoverInformation() (*TimeBasedHandoverInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(350) || v.rowTimeBasedHandoverInformation == nil {
		return nil, false
	}
	return v.rowTimeBasedHandoverInformation, true
}
func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SourceeNBToTargeteNBTransparentContainerExtIEsValue, error) {
	out := SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(175):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.S1APIEsMobilityInformation, error) {
			var v struct {
				Value s00.S1APIEsMobilityInformation
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
		out.rowMobilityInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(194):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UEHistoryInformationFromTheUE, error) {
			var v struct {
				Value s00.UEHistoryInformationFromTheUE
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UEHistoryInformationFromTheUE(val_value)
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
		out.rowUEHistoryInformationFromTheUE = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(296):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IMSvoiceEPSfallbackfrom5G"})
		value := s00.IMSvoiceEPSfallbackfrom5G(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IMSvoiceEPSfallbackfrom5G:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIMSvoiceEPSfallbackfrom5G = &value
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
	case s00.ProtocolIEID(300):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.ContextatSource
		child := scope
		if err := s23.BridgeContextatSourceMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ContextatSource:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ContextatSource")
		if err != nil {
			return out, err
		}
		*s23.BridgeContextatSourceFieldPerPadding(&value) = padding
		*s23.BridgeContextatSourceFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeContextatSourceFieldReceivedBytes(&value))
		*s23.BridgeContextatSourceFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowContextatSource = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(311):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.IntersystemMeasurementConfiguration
		child := scope
		if err := s28.BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "IntersystemMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "IntersystemMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s28.BridgeIntersystemMeasurementConfigurationFieldPerPadding(&value) = padding
		*s28.BridgeIntersystemMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeIntersystemMeasurementConfigurationFieldReceivedBytes(&value))
		*s28.BridgeIntersystemMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowIntersystemMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(312):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s39.SourceNodeID
		child := scope
		if err := s39.BridgeSourceNodeIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceNodeID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SourceNodeID")
		if err != nil {
			return out, err
		}
		*s39.BridgeSourceNodeIDFieldPerPadding(&value) = padding.Padding()
		*s39.BridgeSourceNodeIDFieldReceived(&value) = true
		raw.RetainContents(s39.BridgeSourceNodeIDFieldReceivedBytes(&value))
		*s39.BridgeSourceNodeIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSourceNodeID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(326):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EmergencyIndicator"})
		value := s00.EmergencyIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EmergencyIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEmergencyIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(337):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEContextReferenceatSourceeNB:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEContextReferenceatSourceeNB = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(343):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.GlobalRANNODEID
		child := scope
		if err := s23.BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceSNID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalRANNODEID")
		if err != nil {
			return out, err
		}
		*s23.BridgeGlobalRANNODEIDFieldPerPadding(&value) = padding.Padding()
		*s23.BridgeGlobalRANNODEIDFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeGlobalRANNODEIDFieldReceivedBytes(&value))
		*s23.BridgeGlobalRANNODEIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSourceSNID = &value
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
	case s00.ProtocolIEID(350):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TimeBasedHandoverInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TimeBasedHandoverInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TimeBasedHandoverInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTimeBasedHandoverInformation = &value
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
func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v SourceeNBToTargeteNBTransparentContainerExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(175):
		if v.rowMobilityInformation == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-MobilityInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.S1APIEsMobilityInformation, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.S1APIEsMobilityInformation
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
		})(*v.rowMobilityInformation, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(194):
		if v.rowUEHistoryInformationFromTheUE == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-uE-HistoryInformationFromTheUE:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UEHistoryInformationFromTheUE, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.UEHistoryInformationFromTheUE
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
		})(*v.rowUEHistoryInformationFromTheUE, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(296):
		if v.rowIMSvoiceEPSfallbackfrom5G == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-IMSvoiceEPSfallbackfrom5G:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIMSvoiceEPSfallbackfrom5G), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-AdditionalRRMPriorityIndex:")
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
	case s00.ProtocolIEID(300):
		if v.rowContextatSource == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-ContextatSource:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeContextatSourceMethodMarshalAPERBudget(v.rowContextatSource, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(311):
		if v.rowIntersystemMeasurementConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-IntersystemMeasurementConfiguration:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeIntersystemMeasurementConfigurationMethodMarshalAPERBudget(v.rowIntersystemMeasurementConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(312):
		if v.rowSourceNodeID == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-SourceNodeID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s39.BridgeSourceNodeIDMethodMarshalAPERBudget(v.rowSourceNodeID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(326):
		if v.rowEmergencyIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-EmergencyIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEmergencyIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(337):
		if v.rowUEContextReferenceatSourceeNB == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-UEContextReferenceatSourceeNB:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowUEContextReferenceatSourceeNB), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(343):
		if v.rowSourceSNID == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-SourceSNID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeGlobalRANNODEIDMethodMarshalAPERBudget(v.rowSourceSNID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(79):
		if v.rowDirectForwardingPathAvailability == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-Direct-Forwarding-Path-Availability:")
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
	case s00.ProtocolIEID(350):
		if v.rowTimeBasedHandoverInformation == nil {
			return nil, fmt.Errorf("%s missing value", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-TimeBasedHandoverInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTimeBasedHandoverInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SourceeNBToTargeteNBTransparentContainerExtIEsValue:", v.id)
	}
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
	rowCause                                       *s17.Cause
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
func (v *HandoverRequiredIEValue) AsCause() (*s17.Cause, bool) {
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
		var value s17.Cause
		child := scope
		if err := s17.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s17.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s17.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCauseFieldReceivedBytes(&value))
		*s17.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
	return HandoverRequiredHandoverTypeIEBinding{info: t.infoHandoverType(), codec: func() s01.HandoverTypeValueCodec {
		sealed := s01.HandoverTypeValueCodec{}
		*s01.BridgeHandoverTypeValueCodecFieldPath(&sealed) = "HandoverType"
		*s01.BridgeHandoverTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverType, error) {
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
		*s01.BridgeHandoverTypeValueCodecFieldEncode(&sealed) = func(value s00.HandoverType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(1), rowHandoverType: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeHandoverTypeValueCodecFieldCapture(&sealed) = func(v s00.HandoverType, options aper.DecodeState) (s00.HandoverType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHandoverType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHandoverTypeValueCodecFieldCompare(&sealed) = func(v s00.HandoverType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APHandoverType(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeHandoverTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return HandoverRequiredCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding HandoverRequiredIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s17.Cause, options aper.DecodeState) (s17.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s17.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s17.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.Cause) HandoverRequiredIEValue {
			return HandoverRequiredIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *HandoverRequiredIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
	return HandoverRequiredSRVCCHOIndicationIEBinding{info: t.infoSRVCCHOIndication(), codec: func() s02.SRVCCHOIndicationValueCodec {
		sealed := s02.SRVCCHOIndicationValueCodec{}
		*s02.BridgeSRVCCHOIndicationValueCodecFieldPath(&sealed) = "SRVCCHOIndication"
		*s02.BridgeSRVCCHOIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCHOIndication, error) {
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
		*s02.BridgeSRVCCHOIndicationValueCodecFieldEncode(&sealed) = func(value s00.SRVCCHOIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(125), rowSRVCCHOIndication: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSRVCCHOIndicationValueCodecFieldCapture(&sealed) = func(v s00.SRVCCHOIndication, options aper.DecodeState) (s00.SRVCCHOIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCHOIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeSRVCCHOIndicationValueCodecFieldCompare(&sealed) = func(v s00.SRVCCHOIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSRVCCHOIndication(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeSRVCCHOIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return HandoverRequiredSourceToTargetTransparentContainerIEBinding{info: t.infoSourceToTargetTransparentContainer(), codec: func() s02.SourceToTargetTransparentContainerValueCodec {
		sealed := s02.SourceToTargetTransparentContainerValueCodec{}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldPath(&sealed) = "SourceToTargetTransparentContainer"
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
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
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceToTargetTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(104), rowSourceToTargetTransparentContainer: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceToTargetTransparentContainer, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceToTargetTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceToTargetTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSourceToTargetTransparentContainer(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return HandoverRequiredSourceToTargetTransparentContainerIEBinding{info: t.infoSourceToTargetTransparentContainerSecondary(), codec: func() s02.SourceToTargetTransparentContainerValueCodec {
		sealed := s02.SourceToTargetTransparentContainerValueCodec{}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldPath(&sealed) = "SourceToTargetTransparentContainer"
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
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
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceToTargetTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRequiredIEValue{id: s00.ProtocolIEID(138), rowSourceToTargetTransparentContainerSecondary: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceToTargetTransparentContainer, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSourceToTargetTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceToTargetTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APSourceToTargetTransparentContainer(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeSourceToTargetTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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

// SRVCCHOIndicationCodec binds the complete APER value type.
func SRVCCHOIndicationCodec() s02.SRVCCHOIndicationValueCodec {
	return HandoverRequiredIEs().SRVCCHOIndication().Codec()
}

// TargetIDCodec binds the complete APER value type.
func TargetIDCodec() TargetIDValueCodec { return HandoverRequiredIEs().TargetID().Codec() }

// TargetRNCIDCodec binds the complete source value type.
func TargetRNCIDCodec() TargetRNCIDValueCodec {
	return TargetRNCIDValueCodec{path: "TargetRNCID", decode: func(data []byte, options aper.DecodeState) (s42.TargetRNCID, error) {
		var value s42.TargetRNCID
		if err := s42.BridgeTargetRNCIDMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s42.TargetRNCID{}, err
		}
		*s42.BridgeTargetRNCIDFieldReceived(&value) = true
		*s42.BridgeTargetRNCIDFieldReceivedAbsolute(&value) = true
		*s42.BridgeTargetRNCIDFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s42.TargetRNCID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s42.BridgeTargetRNCIDMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s42.TargetRNCID, options aper.DecodeState) (s42.TargetRNCID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s42.BridgeCaptureS1APTargetRNCID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s42.TargetRNCID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s42.BridgeCompareS1APTargetRNCID(&v, &s)
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

// TargeteNBIDCodec binds the complete source value type.
func TargeteNBIDCodec() TargeteNBIDValueCodec {
	return TargeteNBIDValueCodec{path: "TargeteNBID", decode: func(data []byte, options aper.DecodeState) (TargeteNBID, error) {
		var value TargeteNBID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return TargeteNBID{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value TargeteNBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v TargeteNBID, options aper.DecodeState) (TargeteNBID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APTargeteNBID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TargeteNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APTargeteNBID(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.
			BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargeteNBID"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeENBDirectInformationTransferFieldPerPadding(v *ENBDirectInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeENBDirectInformationTransferIEValueFieldId(v *ENBDirectInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBDirectInformationTransferIEValueFieldIsOpaque(v *ENBDirectInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBDirectInformationTransferIEValueFieldOpaque(v *ENBDirectInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeEDT(v *ENBDirectInformationTransferIEValue) **InterSystemInformationTransferType {
	return &v.rowInterSystemInformationTransferTypeEDT
}
func BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v *ENBDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBDirectInformationTransferMethodUnmarshalAPERFrom(v *ENBDirectInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeHandoverRequiredFieldPerPadding(v *HandoverRequired) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverRequiredFieldReceived(v *HandoverRequired) *bool { return &v.received }
func BridgeHandoverRequiredFieldReceivedAbsolute(v *HandoverRequired) *bool {
	return &v.receivedAbsolute
}
func BridgeHandoverRequiredFieldReceivedBytes(v *HandoverRequired) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverRequiredFieldReceivedLocation(v *HandoverRequired) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(v *HandoverRequiredIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequiredIEValueFieldId(v *HandoverRequiredIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeHandoverRequiredIEValueFieldIsOpaque(v *HandoverRequiredIEValue) *bool       { return &v.isOpaque }
func BridgeHandoverRequiredIEValueFieldOpaque(v *HandoverRequiredIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverRequiredIEValueFieldRowCSGId(v *HandoverRequiredIEValue) **s00.CSGId {
	return &v.rowCSGId
}
func BridgeHandoverRequiredIEValueFieldRowCause(v *HandoverRequiredIEValue) **s17.Cause {
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
func BridgeHandoverRequiredIEValueMethodMatchesID(v HandoverRequiredIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverRequiredMethodMarshalAPERBudget(v *HandoverRequired, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverRequiredMethodUnmarshalAPERFrom(v *HandoverRequired, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequiredMethodUnmarshalAPERWithOptions(v *HandoverRequired, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverRequiredValueCodecFieldCapture(v *HandoverRequiredValueCodec) *func(HandoverRequired, aper.DecodeState) (HandoverRequired, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequiredValueCodecFieldCompare(v *HandoverRequiredValueCodec) *func(HandoverRequired, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequiredValueCodecFieldContext(v *HandoverRequiredValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredValueCodecFieldDecode(v *HandoverRequiredValueCodec) *func([]byte, aper.DecodeState) (HandoverRequired, error) {
	return &v.decode
}
func BridgeHandoverRequiredValueCodecFieldEncode(v *HandoverRequiredValueCodec) *func(HandoverRequired, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequiredValueCodecFieldPath(v *HandoverRequiredValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEDirectInformationTransferFieldPerPadding(v *MMEDirectInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeMMEDirectInformationTransferIEValueFieldId(v *MMEDirectInformationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEDirectInformationTransferIEValueFieldIsOpaque(v *MMEDirectInformationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEDirectInformationTransferIEValueFieldOpaque(v *MMEDirectInformationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEDirectInformationTransferIEValueFieldRowInterSystemInformationTransferTypeMDT(v *MMEDirectInformationTransferIEValue) **InterSystemInformationTransferType {
	return &v.rowInterSystemInformationTransferTypeMDT
}
func BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v *MMEDirectInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEDirectInformationTransferMethodUnmarshalAPERFrom(v *MMEDirectInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding) *func(s00.AdditionalRRMPriorityIndex) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *s23.ContextatSourceValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s23.ContextatSource, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *func(s23.ContextatSource) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *s00.DirectForwardingPathAvailabilityValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.DirectForwardingPathAvailability, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding) *func(s00.DirectForwardingPathAvailability) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding) *func(s00.ENBUES1APID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) *s00.EmergencyIndicatorValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.EmergencyIndicator, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding) *func(s00.EmergencyIndicator) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldCapture(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldCompare(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldContext(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldDecode(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldEncode(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecFieldPath(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValueFieldContext(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValueFieldReceived(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValueFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValueFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldId(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldIsOpaque(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldOpaque(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowAdditionalRRMPriorityIndex(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowContextatSource(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s23.ContextatSource {
	return &v.rowContextatSource
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowDirectForwardingPathAvailability(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.DirectForwardingPathAvailability {
	return &v.rowDirectForwardingPathAvailability
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowEmergencyIndicator(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.EmergencyIndicator {
	return &v.rowEmergencyIndicator
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIMSvoiceEPSfallbackfrom5G(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.IMSvoiceEPSfallbackfrom5G {
	return &v.rowIMSvoiceEPSfallbackfrom5G
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIntersystemMeasurementConfiguration(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s28.IntersystemMeasurementConfiguration {
	return &v.rowIntersystemMeasurementConfiguration
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowMobilityInformation(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.S1APIEsMobilityInformation {
	return &v.rowMobilityInformation
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceNodeID(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s39.SourceNodeID {
	return &v.rowSourceNodeID
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceSNID(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s23.GlobalRANNODEID {
	return &v.rowSourceSNID
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowTimeBasedHandoverInformation(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **TimeBasedHandoverInformation {
	return &v.rowTimeBasedHandoverInformation
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEContextReferenceatSourceeNB(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.ENBUES1APID {
	return &v.rowUEContextReferenceatSourceeNB
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowUEHistoryInformationFromTheUE(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.UEHistoryInformationFromTheUE {
	return &v.rowUEHistoryInformationFromTheUE
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodCaptureSemantics(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 aper.SemanticCapture) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodCompareSemantics(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodDecode(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SourceeNBToTargeteNBTransparentContainerExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodEncodeFresh(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodMatchesID(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodReason(v SourceeNBToTargeteNBTransparentContainerExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodRule(v SourceeNBToTargeteNBTransparentContainerExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeTargeteNBIDMethodMarshalAPERTo(v *TargeteNBID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTargeteNBIDMethodUnmarshalAPERFrom(v *TargeteNBID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
// The field's Id distinguishes alternatives with the same Go type.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 175:
		if value, ok := v.AsMobilityInformation(); ok {
			return value, true
		}
	case 194:
		if value, ok := v.AsUEHistoryInformationFromTheUE(); ok {
			return value, true
		}
	case 296:
		if value, ok := v.AsIMSvoiceEPSfallbackfrom5G(); ok {
			return value, true
		}
	case 299:
		if value, ok := v.AsAdditionalRRMPriorityIndex(); ok {
			return value, true
		}
	case 300:
		if value, ok := v.AsContextatSource(); ok {
			return value, true
		}
	case 311:
		if value, ok := v.AsIntersystemMeasurementConfiguration(); ok {
			return value, true
		}
	case 312:
		if value, ok := v.AsSourceNodeID(); ok {
			return value, true
		}
	case 326:
		if value, ok := v.AsEmergencyIndicator(); ok {
			return value, true
		}
	case 337:
		if value, ok := v.AsUEContextReferenceatSourceeNB(); ok {
			return value, true
		}
	case 343:
		if value, ok := v.AsSourceSNID(); ok {
			return value, true
		}
	case 79:
		if value, ok := v.AsDirectForwardingPathAvailability(); ok {
			return value, true
		}
	case 350:
		if value, ok := v.AsTimeBasedHandoverInformation(); ok {
			return value, true
		}
	}
	return nil, false
}
