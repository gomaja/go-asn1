// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s38 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s38

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
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ENBCPRelocationIndicationIEContainer is ProtocolIE-Container {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of ENBCPRelocationIndicationIEField values.
type ENBCPRelocationIndicationIEContainer []ENBCPRelocationIndicationIEField

// ENBCPRelocationIndicationIEField is ProtocolIE-Field {{ENBCPRelocationIndicationIEs}} of TS 36.413: an information element field.
type ENBCPRelocationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBCPRelocationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEField) WithoutReplay() ENBCPRelocationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBCPRelocationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBCPRelocationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBCPRelocationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBCPRelocationIndicationIEField{}
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
	var zero ENBCPRelocationIndicationIEValue

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

// ENBEarlyStatusTransferIEContainer is ProtocolIE-Container {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of ENBEarlyStatusTransferIEField values.
type ENBEarlyStatusTransferIEContainer []ENBEarlyStatusTransferIEField

// ENBEarlyStatusTransferIEField is ProtocolIE-Field {{ENBEarlyStatusTransferIEs}} of TS 36.413: an information element field.
type ENBEarlyStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBEarlyStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEField) WithoutReplay() ENBEarlyStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBEarlyStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferIEField{}
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
	var zero ENBEarlyStatusTransferIEValue

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

// MMEEarlyStatusTransferIEContainer is ProtocolIE-Container {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of MMEEarlyStatusTransferIEField values.
type MMEEarlyStatusTransferIEContainer []MMEEarlyStatusTransferIEField

// MMEEarlyStatusTransferIEField is ProtocolIE-Field {{MMEEarlyStatusTransferIEs}} of TS 36.413: an information element field.
type MMEEarlyStatusTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEEarlyStatusTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEField) WithoutReplay() MMEEarlyStatusTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEEarlyStatusTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEEarlyStatusTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEEarlyStatusTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEEarlyStatusTransferIEField{}
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
	var zero MMEEarlyStatusTransferIEValue

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
func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(v *ENBCPRelocationIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(v *ENBCPRelocationIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(v *ENBEarlyStatusTransferIEContainer, s *aper.SemanticCapture) {
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
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(v *ENBEarlyStatusTransferIEContainer, s *aper.SemanticComparison) {
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
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(v *MMEEarlyStatusTransferIEContainer, s *aper.SemanticCapture) {
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
			BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(v *MMEEarlyStatusTransferIEContainer, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: a list of ENBEarlyStatusTransferTransparentContainerExtIEsExtField values.
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer []ENBEarlyStatusTransferTransparentContainerExtIEsExtField

// ENBEarlyStatusTransferTransparentContainerExtIEsExtField is ProtocolExtensionField {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} of TS 36.413: an extension field.
type ENBEarlyStatusTransferTransparentContainerExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue ENBEarlyStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtField) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}
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
	var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue

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

// ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding binds BearersSubjectToDLDiscardingList to the ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs object set of TS 36.413.
type ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding struct {
	info   s00.ExtensionInfo
	codec  s15.BearersSubjectToDLDiscardingListValueCodec
	inject func(s15.BearersSubjectToDLDiscardingList,

	) ENBEarlyStatusTransferTransparentContainerExtIEsValue

	get func(*ENBEarlyStatusTransferTransparentContainerExtIEsValue,

	) (*s15.BearersSubjectToDLDiscardingList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Codec() s15.BearersSubjectToDLDiscardingListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) New(value s15.BearersSubjectToDLDiscardingList,

) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Get(field *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) (*s15.BearersSubjectToDLDiscardingList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ENBCPRelocationIndicationENBUES1APIDIEBinding binds ENBUES1APID to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationENBUES1APIDIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationSTMSIIEBinding binds STMSI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s28.STMSI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s28.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationSTMSIIEBinding) New(value s28.STMSI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s28.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationEUTRANCGIIEBinding binds EUTRANCGI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Codec() s18.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) New(value s17.EUTRANCGI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s17.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationTAIIEBinding binds TAI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s32.TAI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s32.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationTAIIEBinding) New(value s32.TAI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s32.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationULCPSecurityInformationIEBinding binds ULCPSecurityInformation to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationULCPSecurityInformationIEBinding struct {
	info   s00.FieldInfo
	codec  ULCPSecurityInformationValueCodec
	inject func(ULCPSecurityInformation,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*ULCPSecurityInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Codec() ULCPSecurityInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) New(value ULCPSecurityInformation,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationULCPSecurityInformationIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*ULCPSecurityInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ULCPSecurityInformationValueCodec is the concrete ValueCodec[ULCPSecurityInformation].
type ULCPSecurityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ULCPSecurityInformation,

		error)
	encode func(ULCPSecurityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ULCPSecurityInformation, aper.DecodeState,

	) (ULCPSecurityInformation, aper.Snapshot,

	)
	compare func(ULCPSecurityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ULCPSecurityInformationValueCodec) New(value ULCPSecurityInformation,

) (ULCPSecurityInformationAPERValue, error) {
	if c.encode == nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULCPSecurityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ULCPSecurityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ULCPSecurityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ULCPSecurityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ULCPSecurityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ULCPSecurityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ULCPSecurityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ULCPSecurityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ULCPSecurityInformationValueCodec) EncodeAPER(value ULCPSecurityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ULCPSecurityInformationValueCodec) encodeBudgetValue(value ULCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ULCPSecurityInformationValueCodec) encodeChanged(value ULCPSecurityInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationLTENTNTAIInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LTENTNTAIInformationValueCodec
	inject func(s18.LTENTNTAIInformation,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s18.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Codec() s18.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) New(value s18.LTENTNTAIInformation,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s18.LTENTNTAIInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferMMEUES1APIDIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferENBUES1APIDIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding binds ENBEarlyStatusTransferTransparentContainer to the ENBEarlyStatusTransferIEs object set of TS 36.413.
type ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBEarlyStatusTransferTransparentContainerValueCodec
	inject func(ENBEarlyStatusTransferTransparentContainer,

	) ENBEarlyStatusTransferIEValue

	get func(*ENBEarlyStatusTransferIEValue,

	) (*ENBEarlyStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Codec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) New(value ENBEarlyStatusTransferTransparentContainer,

) (ENBEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Get(field *ENBEarlyStatusTransferIEField) (*ENBEarlyStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBEarlyStatusTransferTransparentContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainer].
type ENBEarlyStatusTransferTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer,

		error)
	encode func(ENBEarlyStatusTransferTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainer, aper.DecodeState,

	) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot,

	)
	compare func(ENBEarlyStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) New(value ENBEarlyStatusTransferTransparentContainer,

) (ENBEarlyStatusTransferTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UESidelinkAggregateMaximumBitrateValueCodec is the concrete ValueCodec[UESidelinkAggregateMaximumBitrate].
type UESidelinkAggregateMaximumBitrateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UESidelinkAggregateMaximumBitrate,

		error)
	encode func(UESidelinkAggregateMaximumBitrate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UESidelinkAggregateMaximumBitrate, aper.DecodeState,

	) (UESidelinkAggregateMaximumBitrate, aper.Snapshot,

	)
	compare func(UESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UESidelinkAggregateMaximumBitrateValueCodec) New(value UESidelinkAggregateMaximumBitrate,

) (UESidelinkAggregateMaximumBitrateAPERValue, error) {
	if c.encode == nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UESidelinkAggregateMaximumBitrateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UESidelinkAggregateMaximumBitrateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UESidelinkAggregateMaximumBitrateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UESidelinkAggregateMaximumBitrateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UESidelinkAggregateMaximumBitrateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UESidelinkAggregateMaximumBitrateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UESidelinkAggregateMaximumBitrateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UESidelinkAggregateMaximumBitrateValueCodec) EncodeAPER(value UESidelinkAggregateMaximumBitrateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UESidelinkAggregateMaximumBitrateValueCodec) encodeBudgetValue(value UESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UESidelinkAggregateMaximumBitrateValueCodec) encodeChanged(value UESidelinkAggregateMaximumBitrate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferMMEUES1APIDIEBinding binds MMEUES1APID to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferMMEUES1APIDIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEEarlyStatusTransferENBUES1APIDIEBinding binds ENBUES1APID to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferENBUES1APIDIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding binds ENBEarlyStatusTransferTransparentContainer to the MMEEarlyStatusTransferIEs object set of TS 36.413.
type MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding struct {
	info   s00.FieldInfo
	codec  ENBEarlyStatusTransferTransparentContainerValueCodec
	inject func(ENBEarlyStatusTransferTransparentContainer,

	) MMEEarlyStatusTransferIEValue

	get func(*MMEEarlyStatusTransferIEValue,

	) (*ENBEarlyStatusTransferTransparentContainer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Codec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) New(value ENBEarlyStatusTransferTransparentContainer,

) (MMEEarlyStatusTransferIEField, error) {
	if b.inject == nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEEarlyStatusTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) Get(field *MMEEarlyStatusTransferIEField) (*ENBEarlyStatusTransferTransparentContainer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationValueCodec is the concrete ValueCodec[ENBCPRelocationIndication].
type ENBCPRelocationIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndication,

		error)
	encode func(ENBCPRelocationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndication, aper.DecodeState,

	) (ENBCPRelocationIndication, aper.Snapshot,

	)
	compare func(ENBCPRelocationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationValueCodec) New(value ENBCPRelocationIndication,

) (ENBCPRelocationIndicationAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationValueCodec) EncodeAPER(value ENBCPRelocationIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationValueCodec) encodeBudgetValue(value ENBCPRelocationIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationValueCodec) encodeChanged(value ENBCPRelocationIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferValueCodec is the concrete ValueCodec[ENBEarlyStatusTransfer].
type ENBEarlyStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransfer,

		error)
	encode func(ENBEarlyStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransfer, aper.DecodeState,

	) (ENBEarlyStatusTransfer, aper.Snapshot,

	)
	compare func(ENBEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferValueCodec) New(value ENBEarlyStatusTransfer,

) (ENBEarlyStatusTransferAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferValueCodec) EncodeAPER(value ENBEarlyStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferValueCodec) encodeBudgetValue(value ENBEarlyStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferValueCodec) encodeChanged(value ENBEarlyStatusTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferValueCodec is the concrete ValueCodec[MMEEarlyStatusTransfer].
type MMEEarlyStatusTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransfer,

		error)
	encode func(MMEEarlyStatusTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransfer, aper.DecodeState,

	) (MMEEarlyStatusTransfer, aper.Snapshot,

	)
	compare func(MMEEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferValueCodec) New(value MMEEarlyStatusTransfer,

) (MMEEarlyStatusTransferAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferValueCodec) EncodeAPER(value MMEEarlyStatusTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferValueCodec) encodeBudgetValue(value MMEEarlyStatusTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferValueCodec) encodeChanged(value MMEEarlyStatusTransfer,

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
func BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields ENBCPRelocationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(fields ENBEarlyStatusTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(fields MMEEarlyStatusTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ENBEarlyStatusTransferTransparentContainerExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UESidelinkAggregateMaximumBitratesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields s12.ULCPSecurityInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.ULCPSecurityInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.ULCPSecurityInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeULCPSecurityInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// ENBCPRelocationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueERABIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBCPRelocationIndicationIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBCPRelocationIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndicationIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueERABIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ENBEarlyStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ENBEarlyStatusTransferIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferIEValueERABIEContainerListCodec(table s00.ENBEarlyStatusTransferIEValueIETable) ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec {
	codec := ENBEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBEarlyStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
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

// MMEEarlyStatusTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueERABIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable) MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEEarlyStatusTransferIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEEarlyStatusTransferIEValueERABIEContainerList, options aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v MMEEarlyStatusTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable) ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
		var field ENBEarlyStatusTransferTransparentContainerExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainerExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferTransparentContainerExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainerExtIEsExtField")
		}
		return field, nil
	}, encode: func(field ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtField, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable) s12.ULCPSecurityInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.ULCPSecurityInformationExtIEsExtFieldValueCodec {
		sealed := s12.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtField, error) {
			var field s12.ULCPSecurityInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ULCPSecurityInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.ULCPSecurityInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtField, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableCodec(table s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferTransparentContainerExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
		sealed := s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESidelinkAggregateMaximumBitratesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ULCPSecurityInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.ULCPSecurityInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.ULCPSecurityInformationExtIEsExtContainerValueCodec {
		sealed := s12.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.ULCPSecurityInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.ULCPSecurityInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "ULCPSecurityInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.ULCPSecurityInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtContainer, options aper.DecodeState) (s12.ULCPSecurityInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.ULCPSecurityInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueIEFieldTableCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEFieldValueCodec {
	if !*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&table) {
		return ENBCPRelocationIndicationIEFieldValueCodec{}
	}
	return ENBCPRelocationIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEField, error) {
		var field ENBCPRelocationIndicationIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndicationIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEField")
		}
		return field, nil
	}, encode: func(field ENBCPRelocationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBCPRelocationIndicationIEField, options aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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

// ENBEarlyStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ENBEarlyStatusTransferIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferIEValueIEFieldTableCodec(table s00.ENBEarlyStatusTransferIEValueIETable) ENBEarlyStatusTransferIEFieldValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return ENBEarlyStatusTransferIEFieldValueCodec{}
	}
	return ENBEarlyStatusTransferIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEField, error) {
		var field ENBEarlyStatusTransferIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEField")
		}
		return field, nil
	}, encode: func(field ENBEarlyStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ENBEarlyStatusTransferIEField, options aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
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

// MMEEarlyStatusTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueIEFieldTableCodec(table s00.MMEEarlyStatusTransferIEValueIETable) MMEEarlyStatusTransferIEFieldValueCodec {
	if !*s00.BridgeMMEEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return MMEEarlyStatusTransferIEFieldValueCodec{}
	}
	return MMEEarlyStatusTransferIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEField, error) {
		var field MMEEarlyStatusTransferIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEField")
		}
		return field, nil
	}, encode: func(field MMEEarlyStatusTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v MMEEarlyStatusTransferIEField, options aper.DecodeState) (MMEEarlyStatusTransferIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEEarlyStatusTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEField(&v, &s)
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

// ENBCPRelocationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueIETableCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEContainerValueCodec {
	if !*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&table) {
		return ENBCPRelocationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBCPRelocationIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBCPRelocationIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndicationIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ENBCPRelocationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBCPRelocationIndicationIEContainer, options aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBCPRelocationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ENBEarlyStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{ENBEarlyStatusTransferIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferIEValueIETableCodec(table s00.ENBEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) ENBEarlyStatusTransferIEContainerValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return ENBEarlyStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEContainer")
		}
		return fields, nil
	},
		encode: func(fields ENBEarlyStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ENBEarlyStatusTransferIEContainer, options aper.DecodeState) (ENBEarlyStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// MMEEarlyStatusTransferIEValueIETableCodec constructs the ProtocolIE-Container {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueIETableCodec(table s00.MMEEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) MMEEarlyStatusTransferIEContainerValueCodec {
	if !*s00.BridgeMMEEarlyStatusTransferIEValueIETableFieldBound(&table) {
		return MMEEarlyStatusTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return MMEEarlyStatusTransferIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEEarlyStatusTransferIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEContainer")
		}
		return fields, nil
	},
		encode: func(fields MMEEarlyStatusTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v MMEEarlyStatusTransferIEContainer, options aper.DecodeState) (MMEEarlyStatusTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v MMEEarlyStatusTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBCPRelocationIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(
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

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBEarlyStatusTransferIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBEarlyStatusTransferIEValueIETable) ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
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

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{MMEEarlyStatusTransferIEs}} codec of TS 36.413.
func MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable) MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(
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

// ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBCPRelocationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBCPRelocationIndicationIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBCPRelocationIndicationIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndicationIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBCPRelocationIndicationIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBCPRelocationIndicationIEContainer(value), fresh, budget)
	}, capture: func(v ENBCPRelocationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ENBCPRelocationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ENBEarlyStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBEarlyStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBEarlyStatusTransferIEValueProtocolIEContainerListCodec(table s00.ENBEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBEarlyStatusTransferIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ENBEarlyStatusTransferIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ENBEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value ENBEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ENBEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v ENBEarlyStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v ENBEarlyStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {MMEEarlyStatusTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func MMEEarlyStatusTransferIEValueProtocolIEContainerListCodec(table s00.MMEEarlyStatusTransferIEValueIETable, bounds aper.ListBounds) MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEEarlyStatusTransferIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields MMEEarlyStatusTransferIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field MMEEarlyStatusTransferIEField
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
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransferIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "MMEEarlyStatusTransferIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(MMEEarlyStatusTransferIEContainer(value), fresh, budget)
	}, capture: func(v MMEEarlyStatusTransferIEValueProtocolIEContainerList, options aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MMEEarlyStatusTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// eNBCPRelocationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBCPRelocationIndicationIEValue].
type ENBCPRelocationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBCPRelocationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(v *ENBCPRelocationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(v *ENBCPRelocationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eNBEarlyStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBEarlyStatusTransferIEValue].
type ENBEarlyStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBEarlyStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBEarlyStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v *ENBEarlyStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(v *ENBEarlyStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// eNBEarlyStatusTransferTransparentContainerExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ENBEarlyStatusTransferTransparentContainerExtIEsValue].
type ENBEarlyStatusTransferTransparentContainerExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ENBEarlyStatusTransferTransparentContainerExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ENBEarlyStatusTransferTransparentContainerExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mMEEarlyStatusTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEEarlyStatusTransferIEValue].
type MMEEarlyStatusTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) MMEEarlyStatusTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (MMEEarlyStatusTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v *MMEEarlyStatusTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEField(v *MMEEarlyStatusTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESidelinkAggregateMaximumBitratesExtIEsValue].
type UESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UESidelinkAggregateMaximumBitratesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UESidelinkAggregateMaximumBitratesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uLCPSecurityInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ULCPSecurityInformationExtIEsValue].
type ULCPSecurityInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ULCPSecurityInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ULCPSecurityInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeULCPSecurityInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeULCPSecurityInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// ULCPSecurityInformationAPERValue is the concrete APERValue[ULCPSecurityInformation].
type ULCPSecurityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ULCPSecurityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ULCPSecurityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ULCPSecurityInformationAPERValue) WithoutReplay() ULCPSecurityInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainer].
type ENBEarlyStatusTransferTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBEarlyStatusTransferTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UESidelinkAggregateMaximumBitrateAPERValue is the concrete APERValue[UESidelinkAggregateMaximumBitrate].
type UESidelinkAggregateMaximumBitrateAPERValue struct {
	context s00.BridgeCodecContext
	Value   UESidelinkAggregateMaximumBitrate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UESidelinkAggregateMaximumBitrateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UESidelinkAggregateMaximumBitrateAPERValue) WithoutReplay() UESidelinkAggregateMaximumBitrateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationAPERValue is the concrete APERValue[ENBCPRelocationIndication].
type ENBCPRelocationIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBCPRelocationIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationAPERValue) WithoutReplay() ENBCPRelocationIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferAPERValue is the concrete APERValue[ENBEarlyStatusTransfer].
type ENBEarlyStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENBEarlyStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferAPERValue) WithoutReplay() ENBEarlyStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferAPERValue is the concrete APERValue[MMEEarlyStatusTransfer].
type MMEEarlyStatusTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   MMEEarlyStatusTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferAPERValue) WithoutReplay() MMEEarlyStatusTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerExtIEsIEField uses the ProtocolIE-Field shape for object set ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs of TS 36.413.
type ENBEarlyStatusTransferTransparentContainerExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsIEField) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainerExtIEsIEField{}
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
	var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue

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

// ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer uses the ProtocolIE-Container shape for object set ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs of TS 36.413: a list of ENBEarlyStatusTransferTransparentContainerExtIEsIEField values.
type ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer []ENBEarlyStatusTransferTransparentContainerExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APIEContainer(fields ENBEarlyStatusTransferTransparentContainerExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(fields s12.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeULCPSecurityInformationExtIEsValueValidateS1APIEContainer(fields s12.ULCPSecurityInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeULCPSecurityInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value).Assignment
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

// ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueERABIEContainerList].
type ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueERABIEContainerList) (ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type ENBCPRelocationIndicationIEValueERABIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APERABIEContainerList(v *ENBCPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APERABIEContainerList(v *ENBCPRelocationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueERABIEContainerList].
type ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueERABIEContainerList) (ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBEarlyStatusTransferIEValueERABIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(v *ENBEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APERABIEContainerList(v *ENBEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueERABIEContainerList].
type MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueERABIEContainerList) (MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEEarlyStatusTransferIEValueERABIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeMMEEarlyStatusTransferIEValueCaptureS1APERABIEContainerList(v *MMEEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APERABIEContainerList(v *MMEEarlyStatusTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainerExtIEsExtField].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error)
	encode  func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot)
	compare func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) New(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField) (ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error)
	encode  func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot)
	compare func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) New(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEFieldValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEField].
type ENBCPRelocationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEField, error)
	encode  func(ENBCPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEField, aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEFieldValueCodec) New(value ENBCPRelocationIndicationIEField) (ENBCPRelocationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEFieldValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEFieldValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEFieldValueCodec) encodeChanged(value ENBCPRelocationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEFieldValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEField].
type ENBEarlyStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEField, error)
	encode  func(ENBEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEField, aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEFieldValueCodec) New(value ENBEarlyStatusTransferIEField) (ENBEarlyStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEFieldValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEFieldValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEFieldValueCodec) encodeChanged(value ENBEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEFieldValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEField].
type MMEEarlyStatusTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEField, error)
	encode  func(MMEEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEField, aper.DecodeState) (MMEEarlyStatusTransferIEField, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEFieldValueCodec) New(value MMEEarlyStatusTransferIEField) (MMEEarlyStatusTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEFieldValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEFieldValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEFieldValueCodec) encodeChanged(value MMEEarlyStatusTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEContainerValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEContainer].
type ENBCPRelocationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error)
	encode  func(ENBCPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEContainer, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEContainerValueCodec) New(value ENBCPRelocationIndicationIEContainer) (ENBCPRelocationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEContainerValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEContainerValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEContainerValueCodec) encodeChanged(value ENBCPRelocationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEContainerValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEContainer].
type ENBEarlyStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error)
	encode  func(ENBEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEContainer, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEContainerValueCodec) New(value ENBEarlyStatusTransferIEContainer) (ENBEarlyStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEContainerValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEContainerValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEContainerValueCodec) encodeChanged(value ENBEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEContainerValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEContainer].
type MMEEarlyStatusTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, error)
	encode  func(MMEEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEContainer, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEContainerValueCodec) New(value MMEEarlyStatusTransferIEContainer) (MMEEarlyStatusTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEContainerValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEContainerValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEContainerValueCodec) encodeChanged(value MMEEarlyStatusTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBCPRelocationIndicationIEs}} of TS 36.413: a list of information element fields.
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEEarlyStatusTransferIEs}} of TS 36.413: a list of information element fields.
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolErrorIEContainerList(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBCPRelocationIndicationIEValueProtocolIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error)
	encode  func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) New(value ENBCPRelocationIndicationIEValueProtocolIEContainerList) (ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBCPRelocationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBCPRelocationIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBCPRelocationIndicationIEValueProtocolIEContainerList []ENBCPRelocationIndicationIEValueProtocolIESingleContainer

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainerList(v *ENBCPRelocationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBEarlyStatusTransferIEValueProtocolIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) New(value ENBEarlyStatusTransferIEValueProtocolIEContainerList) (ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBEarlyStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBEarlyStatusTransferIEValueProtocolIEContainerList []ENBEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(v *ENBEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEEarlyStatusTransferIEValueProtocolIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, error)
	encode  func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) New(value MMEEarlyStatusTransferIEValueProtocolIEContainerList) (MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEEarlyStatusTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEEarlyStatusTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEEarlyStatusTransferIEValueProtocolIEContainerList []MMEEarlyStatusTransferIEValueProtocolIESingleContainer

func BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainerList(v *MMEEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainerList(v *MMEEarlyStatusTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueERABIEContainerList].
type ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBCPRelocationIndicationIEs}} of TS 36.413: a single information element field.
type ENBCPRelocationIndicationIEValueProtocolIESingleContainer = ENBCPRelocationIndicationIEField

func BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *ENBCPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIESingleContainer(v *ENBCPRelocationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueERABIEContainerList].
type ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBEarlyStatusTransferIEs}} of TS 36.413: a single information element field.
type ENBEarlyStatusTransferIEValueProtocolIESingleContainer = ENBEarlyStatusTransferIEField

func BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *ENBEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *ENBEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueERABIEContainerList].
type MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEEarlyStatusTransferIEs}} of TS 36.413: a single information element field.
type MMEEarlyStatusTransferIEValueProtocolIESingleContainer = MMEEarlyStatusTransferIEField

func BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIESingleContainer(v *MMEEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIESingleContainer(v *MMEEarlyStatusTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainerExtIEsExtField].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer].
type ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEFieldAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEField].
type ENBCPRelocationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEFieldAPERValue) WithoutReplay() ENBCPRelocationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEFieldAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEField].
type ENBEarlyStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEFieldAPERValue) WithoutReplay() ENBEarlyStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEFieldAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEField].
type MMEEarlyStatusTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEFieldAPERValue) WithoutReplay() MMEEarlyStatusTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEContainerAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEContainer].
type ENBCPRelocationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEContainerAPERValue) WithoutReplay() ENBCPRelocationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEContainerAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEContainer].
type ENBEarlyStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEContainerAPERValue) WithoutReplay() ENBEarlyStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEContainerAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEContainer].
type MMEEarlyStatusTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEContainerAPERValue) WithoutReplay() MMEEarlyStatusTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBCPRelocationIndicationIEValueProtocolIEContainerList].
type ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBCPRelocationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBEarlyStatusTransferIEValueProtocolIEContainerList].
type ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBEarlyStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEEarlyStatusTransferIEValueProtocolIEContainerList].
type MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEEarlyStatusTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APActivatedCellsListComplete(v *ActivatedCellsListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APActivatedCellsList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APActivatedCellsListComplete(v *ActivatedCellsListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APActivatedCellsList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBPLMNsComplete(v *BPLMNsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBPLMNs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBPLMNsComplete(v *BPLMNsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APBPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferListComplete(v *BearersSubjectToEarlyStatusTransferListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v *BearersSubjectToEarlyStatusTransferListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToStatusTransferListComplete(v *BearersSubjectToStatusTransferListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToStatusTransferList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v *BearersSubjectToStatusTransferListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToStatusTransferList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBluetoothMeasConfigNameListComplete(v *BluetoothMeasConfigNameListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBluetoothMeasConfigNameListComplete(v *BluetoothMeasConfigNameListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCNTypeRestrictionsComplete(v *CNTypeRestrictionsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCNTypeRestrictions(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCNTypeRestrictionsComplete(v *CNTypeRestrictionsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCNTypeRestrictions(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCSGIdListComplete(v *CSGIdListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCSGIdList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCSGIdListComplete(v *CSGIdListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCSGIdList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinEAIComplete(v *CancelledCellinEAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCancelledCellinEAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinEAIComplete(v *CancelledCellinEAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCancelledCellinEAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCancelledCellinTAIComplete(v *CancelledCellinTAIComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCancelledCellinTAI(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCancelledCellinTAIComplete(v *CancelledCellinTAIComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCancelledCellinTAI(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidateCellListComplete(v *CandidateCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCandidateCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidateCellListComplete(v *CandidateCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCandidateCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCandidatePCIListComplete(v *CandidatePCIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCandidatePCIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCandidatePCIListComplete(v *CandidatePCIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCandidatePCIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDBroadcastComplete(v *CellIDBroadcastComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIDBroadcast(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDBroadcastComplete(v *CellIDBroadcastComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCellIDBroadcast(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIDCancelledComplete(v *CellIDCancelledComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIDCancelled(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIDCancelledComplete(v *CellIDCancelledComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCellIDCancelled(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIdListforMDTComplete(v *CellIdListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIdListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIdListforMDTComplete(v *CellIdListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCellIdListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APCellIdListforQMCComplete(v *CellIdListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APCellIdListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APCellIdListforQMCComplete(v *CellIdListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s22.BridgeCompareS1APCellIdListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBCPRelocationIndication(v *ENBCPRelocationIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBCPRelocationIndication(v *ENBCPRelocationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBCPRelocationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBCPRelocationIndicationIEValue(v *ENBCPRelocationIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
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
					s32.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(254):
			{
				f := s.Begin()
				s.Bool(v.rowULCPSecurityInformation == nil)
				if v.rowULCPSecurityInformation != nil {
					BridgeCaptureS1APULCPSecurityInformation(v.rowULCPSecurityInformation, s)
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
func (v ENBCPRelocationIndicationIEValue) captureSemantics(s aper.SemanticCapture) ENBCPRelocationIndicationIEValue {
	BridgeCaptureS1APENBCPRelocationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBCPRelocationIndicationIEValue(v *ENBCPRelocationIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(96):
			{
				f := s.Begin()
				s.Bool(v.rowSTMSI == nil)
				if v.rowSTMSI != nil {
					s28.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
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
					s32.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(254):
			{
				f := s.Begin()
				s.Bool(v.rowULCPSecurityInformation == nil)
				if v.rowULCPSecurityInformation != nil {
					BridgeCompareS1APULCPSecurityInformation(v.rowULCPSecurityInformation, s)
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
func (v ENBCPRelocationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBCPRelocationIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBEarlyStatusTransfer(v *ENBEarlyStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBEarlyStatusTransfer(v *ENBEarlyStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBEarlyStatusTransferIEValue(v *ENBEarlyStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBEarlyStatusTransferIEValue {
	BridgeCaptureS1APENBEarlyStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBEarlyStatusTransferIEValue(v *ENBEarlyStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBEarlyStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferTransparentContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferTransparentContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
	s.Bool(v.IEExtensions == nil)
	BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(352):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingList == nil)
				if v.rowBearersSubjectToDLDiscardingList != nil {
					s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) captureSemantics(s aper.SemanticCapture) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	BridgeCaptureS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(352):
			{
				f := s.Begin()
				s.Bool(v.rowBearersSubjectToDLDiscardingList == nil)
				if v.rowBearersSubjectToDLDiscardingList != nil {
					s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBEarlyStatusTransferTransparentContainerExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APMMEEarlyStatusTransfer(v *MMEEarlyStatusTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEEarlyStatusTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APMMEEarlyStatusTransfer(v *MMEEarlyStatusTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEEarlyStatusTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEEarlyStatusTransferIEValue(v *MMEEarlyStatusTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEEarlyStatusTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEEarlyStatusTransferIEValue {
	BridgeCaptureS1APMMEEarlyStatusTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEEarlyStatusTransferIEValue(v *MMEEarlyStatusTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(321):
			{
				f := s.Begin()
				s.Bool(v.rowENBEarlyStatusTransferTransparentContainer == nil)
				if v.rowENBEarlyStatusTransferTransparentContainer != nil {
					BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v.rowENBEarlyStatusTransferTransparentContainer, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEEarlyStatusTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEEarlyStatusTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v *UESidelinkAggregateMaximumBitrate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.UESidelinkAggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s37.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v *UESidelinkAggregateMaximumBitrate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APBitRate(&v.UESidelinkAggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	s37.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APULCPSecurityInformation(v *ULCPSecurityInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APULNASMAC(&v.UlNASMAC, s)
	s00.BridgeCaptureS1APULNASCount(&v.UlNASCount, s)
	s.Bool(v.IEExtensions == nil)
	BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APULCPSecurityInformation(v *ULCPSecurityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APULNASMAC(&v.UlNASMAC, s)
	s07.BridgeCompareS1APULNASCount(&v.UlNASCount, s)
	s.Bool(v.IEExtensions == nil)
	BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// ENBEarlyStatusTransferTransparentContainer represents the ASN.1 type ENB-EarlyStatusTransfer-TransparentContainer (SEQUENCE).
type ENBEarlyStatusTransferTransparentContainer struct {
	replay                                       aper.Snapshot
	stream                                       aper.WireSpan
	received                                     bool
	withoutReplay                                bool
	receivedAbsolute                             bool
	receivedBytes                                aper.WireSpan
	receivedLocation                             aper.Location
	BearersSubjectToEarlyStatusTransferList      s15.BearersSubjectToEarlyStatusTransferList                  `asn1:"tag:0,context,implicit"`
	bearersSubjectToEarlyStatusTransferListIndef bool                                                         `asn1:"-" json:"-"`
	IEExtensions                                 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                            bool                                                         `asn1:"-" json:"-"`
	extCount                                     int64                                                        `asn1:"-" json:"-"`
	extPresent                                   []bool                                                       `asn1:"-" json:"-"`
	extData                                      [][]byte                                                     `asn1:"-" json:"-"`
	perPadding                                   aper.FinalPadding                                            `asn1:"-" json:"-"`
	perExtPadding                                []aper.CompletePadding                                       `asn1:"-" json:"-"`
	extOrigin                                    []aper.OpaqueOrigin
	extWire                                      []aper.WireSpan
}

// UESidelinkAggregateMaximumBitrate represents the ASN.1 type UESidelinkAggregateMaximumBitrate (SEQUENCE).
type UESidelinkAggregateMaximumBitrate struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	UESidelinkAggregateMaximumBitRate s00.BitRate                                              `asn1:"tag:0,context,implicit"`
	IEExtensions                      s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                 bool                                                     `asn1:"-" json:"-"`
	extCount                          int64                                                    `asn1:"-" json:"-"`
	extPresent                        []bool                                                   `asn1:"-" json:"-"`
	extData                           [][]byte                                                 `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding                                        `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding                                   `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// ULCPSecurityInformation represents the ASN.1 type UL-CP-SecurityInformation (SEQUENCE).
type ULCPSecurityInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	UlNASMAC          s00.ULNASMAC                                  `asn1:"tag:0,context,implicit"`
	UlNASCount        s00.ULNASCount                                `asn1:"tag:1,context,implicit"`
	IEExtensions      s12.ULCPSecurityInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// BearersSubjectToStatusTransferListComplete carries a complete BearersSubjectToStatusTransferList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToStatusTransferListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s21.BearersSubjectToStatusTransferList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToStatusTransferListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERBearersSubjectToStatusTransferListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToStatusTransferList from APER format.
func (v *BearersSubjectToStatusTransferListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToStatusTransferList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToStatusTransferListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	bb.EnterComponent("BearersSubjectToStatusTransferList")
	value, err := BridgeUnmarshalAPERBearersSubjectToStatusTransferListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToStatusTransferList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToStatusTransferList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBearersSubjectToStatusTransferList encodes a BearersSubjectToStatusTransferList list to APER.
func BridgeMarshalAPERBearersSubjectToStatusTransferList(list BearersSubjectToStatusTransferListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBearersSubjectToStatusTransferList decodes a BearersSubjectToStatusTransferList list from APER.
func BridgeUnmarshalAPERBearersSubjectToStatusTransferList(data []byte) (BearersSubjectToStatusTransferListComplete, error) {
	var value BearersSubjectToStatusTransferListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBearersSubjectToStatusTransferListFrom decodes a BearersSubjectToStatusTransferList list from bb.
func BridgeUnmarshalAPERBearersSubjectToStatusTransferListFrom(bb *aper.BitBuffer) (s21.BearersSubjectToStatusTransferList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToStatusTransferListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToStatusTransferListInto(v *s21.BridgeAsn1cAPERBearersSubjectToStatusTransferListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s21.BearersSubjectToStatusTransferList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s21.BearersSubjectToStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s21.BridgeBearersSubjectToStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// BearersSubjectToEarlyStatusTransferListComplete carries a complete BearersSubjectToEarlyStatusTransferList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToEarlyStatusTransferListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s15.BearersSubjectToEarlyStatusTransferList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToEarlyStatusTransferList from APER format.
func (v *BearersSubjectToEarlyStatusTransferListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToEarlyStatusTransferList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToEarlyStatusTransferListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	bb.EnterComponent("BearersSubjectToEarlyStatusTransferList")
	value, err := BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToEarlyStatusTransferList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToEarlyStatusTransferList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBearersSubjectToEarlyStatusTransferList encodes a BearersSubjectToEarlyStatusTransferList list to APER.
func BridgeMarshalAPERBearersSubjectToEarlyStatusTransferList(list BearersSubjectToEarlyStatusTransferListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferList decodes a BearersSubjectToEarlyStatusTransferList list from APER.
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferList(data []byte) (BearersSubjectToEarlyStatusTransferListComplete, error) {
	var value BearersSubjectToEarlyStatusTransferListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom decodes a BearersSubjectToEarlyStatusTransferList list from bb.
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListFrom(bb *aper.BitBuffer) (s15.BearersSubjectToEarlyStatusTransferList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToEarlyStatusTransferListInto(v *s21.BridgeAsn1cAPERBearersSubjectToEarlyStatusTransferListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s15.BearersSubjectToEarlyStatusTransferList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// BearersSubjectToDLDiscardingListComplete carries a complete BearersSubjectToDLDiscardingList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BearersSubjectToDLDiscardingListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s15.BearersSubjectToDLDiscardingList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToDLDiscardingList from APER format.
func (v *BearersSubjectToDLDiscardingListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BearersSubjectToDLDiscardingList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BearersSubjectToDLDiscardingListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	bb.EnterComponent("BearersSubjectToDLDiscardingList")
	value, err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BearersSubjectToDLDiscardingList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBearersSubjectToDLDiscardingList encodes a BearersSubjectToDLDiscardingList list to APER.
func BridgeMarshalAPERBearersSubjectToDLDiscardingList(list BearersSubjectToDLDiscardingListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBearersSubjectToDLDiscardingList decodes a BearersSubjectToDLDiscardingList list from APER.
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingList(data []byte) (BearersSubjectToDLDiscardingListComplete, error) {
	var value BearersSubjectToDLDiscardingListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBearersSubjectToDLDiscardingListFrom decodes a BearersSubjectToDLDiscardingList list from bb.
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(bb *aper.BitBuffer) (s15.BearersSubjectToDLDiscardingList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(v *s21.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s15.BearersSubjectToDLDiscardingList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s15.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s15.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// BluetoothMeasConfigNameListComplete carries a complete BluetoothMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BluetoothMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.BluetoothMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BluetoothMeasConfigNameListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERBluetoothMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BluetoothMeasConfigNameList from APER format.
func (v *BluetoothMeasConfigNameListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BluetoothMeasConfigNameList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BluetoothMeasConfigNameListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	bb.EnterComponent("BluetoothMeasConfigNameList")
	value, err := BridgeUnmarshalAPERBluetoothMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "BluetoothMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "BluetoothMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBluetoothMeasConfigNameList encodes a BluetoothMeasConfigNameList list to APER.
func BridgeMarshalAPERBluetoothMeasConfigNameList(list BluetoothMeasConfigNameListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERBluetoothMeasConfigNameList decodes a BluetoothMeasConfigNameList list from APER.
func BridgeUnmarshalAPERBluetoothMeasConfigNameList(data []byte) (BluetoothMeasConfigNameListComplete, error) {
	var value BluetoothMeasConfigNameListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBluetoothMeasConfigNameListFrom decodes a BluetoothMeasConfigNameList list from bb.
func BridgeUnmarshalAPERBluetoothMeasConfigNameListFrom(bb *aper.BitBuffer) (s00.BluetoothMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERBluetoothMeasConfigNameListListValue
	if err := BridgeUnmarshalAPERBluetoothMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBluetoothMeasConfigNameListInto(v *s00.BridgeAsn1cAPERBluetoothMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.BluetoothMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 248, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// BPLMNsComplete carries a complete BPLMNs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type BPLMNsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.BPLMNs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BPLMNsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERBPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BPLMNs from APER format.
func (v *BPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes BPLMNs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *BPLMNsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	bb.EnterComponent("BPLMNs")
	value, err := BridgeUnmarshalAPERBPLMNsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	padding, err := aper.CaptureFinalBits(bb, "BPLMNs")
	if err != nil {
		return runtime.WrapDecodePath(err, "BPLMNs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERBPLMNs encodes a BPLMNs list to APER.
func BridgeMarshalAPERBPLMNs(list BPLMNsComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPERBPLMNs decodes a BPLMNs list from APER.
func BridgeUnmarshalAPERBPLMNs(data []byte) (BPLMNsComplete, error) {
	var value BPLMNsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERBPLMNsFrom decodes a BPLMNs list from bb.
func BridgeUnmarshalAPERBPLMNsFrom(bb *aper.BitBuffer) (s00.BPLMNs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERBPLMNsListValue
	if err := BridgeUnmarshalAPERBPLMNsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBPLMNsInto(v *s00.BridgeAsn1cAPERBPLMNsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.BPLMNs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 6, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CancelledCellinEAIComplete carries a complete CancelledCellinEAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CancelledCellinEAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CancelledCellinEAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CancelledCellinEAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCancelledCellinEAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CancelledCellinEAI from APER format.
func (v *CancelledCellinEAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CancelledCellinEAI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CancelledCellinEAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	bb.EnterComponent("CancelledCellinEAI")
	value, err := BridgeUnmarshalAPERCancelledCellinEAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinEAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinEAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCancelledCellinEAI encodes a CancelledCellinEAI list to APER.
func BridgeMarshalAPERCancelledCellinEAI(list CancelledCellinEAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCancelledCellinEAI decodes a CancelledCellinEAI list from APER.
func BridgeUnmarshalAPERCancelledCellinEAI(data []byte) (CancelledCellinEAIComplete, error) {
	var value CancelledCellinEAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCancelledCellinEAIFrom decodes a CancelledCellinEAI list from bb.
func BridgeUnmarshalAPERCancelledCellinEAIFrom(bb *aper.BitBuffer) (s17.CancelledCellinEAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCancelledCellinEAIListValue
	if err := BridgeUnmarshalAPERCancelledCellinEAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCancelledCellinEAIInto(v *s21.BridgeAsn1cAPERCancelledCellinEAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CancelledCellinEAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CancelledCellinEAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCancelledCellinEAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CancelledCellinTAIComplete carries a complete CancelledCellinTAI encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CancelledCellinTAIComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CancelledCellinTAI
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CancelledCellinTAIComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCancelledCellinTAITo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CancelledCellinTAI from APER format.
func (v *CancelledCellinTAIComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CancelledCellinTAI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CancelledCellinTAIComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	bb.EnterComponent("CancelledCellinTAI")
	value, err := BridgeUnmarshalAPERCancelledCellinTAIFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	padding, err := aper.CaptureFinalBits(bb, "CancelledCellinTAI")
	if err != nil {
		return runtime.WrapDecodePath(err, "CancelledCellinTAI")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCancelledCellinTAI encodes a CancelledCellinTAI list to APER.
func BridgeMarshalAPERCancelledCellinTAI(list CancelledCellinTAIComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCancelledCellinTAI decodes a CancelledCellinTAI list from APER.
func BridgeUnmarshalAPERCancelledCellinTAI(data []byte) (CancelledCellinTAIComplete, error) {
	var value CancelledCellinTAIComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCancelledCellinTAIFrom decodes a CancelledCellinTAI list from bb.
func BridgeUnmarshalAPERCancelledCellinTAIFrom(bb *aper.BitBuffer) (s17.CancelledCellinTAI, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCancelledCellinTAIListValue
	if err := BridgeUnmarshalAPERCancelledCellinTAIInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCancelledCellinTAIInto(v *s21.BridgeAsn1cAPERCancelledCellinTAIListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CancelledCellinTAI, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CancelledCellinTAIItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCancelledCellinTAIItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIDBroadcastComplete carries a complete CellIDBroadcast encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIDBroadcastComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CellIDBroadcast
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIDBroadcastComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCellIDBroadcastTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIDBroadcast from APER format.
func (v *CellIDBroadcastComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellIDBroadcast with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellIDBroadcastComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	bb.EnterComponent("CellIDBroadcast")
	value, err := BridgeUnmarshalAPERCellIDBroadcastFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDBroadcast")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDBroadcast")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIDBroadcast encodes a CellIDBroadcast list to APER.
func BridgeMarshalAPERCellIDBroadcast(list CellIDBroadcastComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIDBroadcast decodes a CellIDBroadcast list from APER.
func BridgeUnmarshalAPERCellIDBroadcast(data []byte) (CellIDBroadcastComplete, error) {
	var value CellIDBroadcastComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIDBroadcastFrom decodes a CellIDBroadcast list from bb.
func BridgeUnmarshalAPERCellIDBroadcastFrom(bb *aper.BitBuffer) (s17.CellIDBroadcast, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCellIDBroadcastListValue
	if err := BridgeUnmarshalAPERCellIDBroadcastInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIDBroadcastInto(v *s21.BridgeAsn1cAPERCellIDBroadcastListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CellIDBroadcast, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CellIDBroadcastItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCellIDBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIDCancelledComplete carries a complete CellIDCancelled encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIDCancelledComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CellIDCancelled
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIDCancelledComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCellIDCancelledTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIDCancelled from APER format.
func (v *CellIDCancelledComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellIDCancelled with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellIDCancelledComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	bb.EnterComponent("CellIDCancelled")
	value, err := BridgeUnmarshalAPERCellIDCancelledFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIDCancelled")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIDCancelled")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIDCancelled encodes a CellIDCancelled list to APER.
func BridgeMarshalAPERCellIDCancelled(list CellIDCancelledComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIDCancelled decodes a CellIDCancelled list from APER.
func BridgeUnmarshalAPERCellIDCancelled(data []byte) (CellIDCancelledComplete, error) {
	var value CellIDCancelledComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIDCancelledFrom decodes a CellIDCancelled list from bb.
func BridgeUnmarshalAPERCellIDCancelledFrom(bb *aper.BitBuffer) (s17.CellIDCancelled, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCellIDCancelledListValue
	if err := BridgeUnmarshalAPERCellIDCancelledInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIDCancelledInto(v *s21.BridgeAsn1cAPERCellIDCancelledListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CellIDCancelled, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.CellIDCancelledItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeCellIDCancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIdListforMDTComplete carries a complete CellIdListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIdListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CellIdListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIdListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCellIdListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIdListforMDT from APER format.
func (v *CellIdListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellIdListforMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellIdListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	bb.EnterComponent("CellIdListforMDT")
	value, err := BridgeUnmarshalAPERCellIdListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIdListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCellIdListforMDT encodes a CellIdListforMDT list to APER.
func BridgeMarshalAPERCellIdListforMDT(list CellIdListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCellIdListforMDT decodes a CellIdListforMDT list from APER.
func BridgeUnmarshalAPERCellIdListforMDT(data []byte) (CellIdListforMDTComplete, error) {
	var value CellIdListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCellIdListforMDTFrom decodes a CellIdListforMDT list from bb.
func BridgeUnmarshalAPERCellIdListforMDTFrom(bb *aper.BitBuffer) (s17.CellIdListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCellIdListforMDTListValue
	if err := BridgeUnmarshalAPERCellIdListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIdListforMDTInto(v *s21.BridgeAsn1cAPERCellIdListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CellIdListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CellIdListforQMCComplete carries a complete CellIdListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CellIdListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s17.CellIdListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CellIdListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCellIdListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CellIdListforQMC from APER format.
func (v *CellIdListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellIdListforQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CellIdListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	bb.EnterComponent("CellIdListforQMC")
	value, err := BridgeUnmarshalAPERCellIdListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellIdListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellIdListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// UnmarshalAPERCellIdListforQMCFrom decodes a CellIdListforQMC list from bb.
func BridgeUnmarshalAPERCellIdListforQMCFrom(bb *aper.BitBuffer) (s17.CellIdListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCellIdListforQMCListValue
	if err := BridgeUnmarshalAPERCellIdListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCellIdListforQMCInto(v *s21.BridgeAsn1cAPERCellIdListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.CellIdListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.EUTRANCGI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CNTypeRestrictionsComplete carries a complete CNTypeRestrictions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CNTypeRestrictionsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s14.CNTypeRestrictions
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CNTypeRestrictionsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCNTypeRestrictionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CNTypeRestrictions from APER format.
func (v *CNTypeRestrictionsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CNTypeRestrictions with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CNTypeRestrictionsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	bb.EnterComponent("CNTypeRestrictions")
	value, err := BridgeUnmarshalAPERCNTypeRestrictionsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	padding, err := aper.CaptureFinalBits(bb, "CNTypeRestrictions")
	if err != nil {
		return runtime.WrapDecodePath(err, "CNTypeRestrictions")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCNTypeRestrictions encodes a CNTypeRestrictions list to APER.
func BridgeMarshalAPERCNTypeRestrictions(list CNTypeRestrictionsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCNTypeRestrictions decodes a CNTypeRestrictions list from APER.
func BridgeUnmarshalAPERCNTypeRestrictions(data []byte) (CNTypeRestrictionsComplete, error) {
	var value CNTypeRestrictionsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCNTypeRestrictionsFrom decodes a CNTypeRestrictions list from bb.
func BridgeUnmarshalAPERCNTypeRestrictionsFrom(bb *aper.BitBuffer) (s14.CNTypeRestrictions, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCNTypeRestrictionsListValue
	if err := BridgeUnmarshalAPERCNTypeRestrictionsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCNTypeRestrictionsInto(v *s21.BridgeAsn1cAPERCNTypeRestrictionsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.CNTypeRestrictions, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.CNTypeRestrictionsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeCNTypeRestrictionsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CSGIdListComplete carries a complete CSGIdList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CSGIdListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s14.CSGIdList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CSGIdListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCSGIdListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CSGIdList from APER format.
func (v *CSGIdListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CSGIdList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CSGIdListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	bb.EnterComponent("CSGIdList")
	value, err := BridgeUnmarshalAPERCSGIdListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CSGIdList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CSGIdList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCSGIdList encodes a CSGIdList list to APER.
func BridgeMarshalAPERCSGIdList(list CSGIdListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCSGIdList decodes a CSGIdList list from APER.
func BridgeUnmarshalAPERCSGIdList(data []byte) (CSGIdListComplete, error) {
	var value CSGIdListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCSGIdListFrom decodes a CSGIdList list from bb.
func BridgeUnmarshalAPERCSGIdListFrom(bb *aper.BitBuffer) (s14.CSGIdList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCSGIdListListValue
	if err := BridgeUnmarshalAPERCSGIdListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCSGIdListInto(v *s21.BridgeAsn1cAPERCSGIdListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.CSGIdList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.CSGIdListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeCSGIdListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes ENBEarlyStatusTransferTransparentContainer to APER format.
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.BearersSubjectToEarlyStatusTransferList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList)) || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist : fragmentOffset_bearerssubjecttoearlystatustransferlist+fragmentLength_bearerssubjecttoearlystatustransferlist] {
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding bearers-SubjectToEarlyStatusTransferList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bearers-SubjectToEarlyStatusTransferList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBEarlyStatusTransferTransparentContainer from APER format.
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBEarlyStatusTransferTransparentContainer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	bb.EnterComponent("ENBEarlyStatusTransferTransparentContainer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransferTransparentContainer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainer{}
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
	toleranceMark_bearerssubjecttoearlystatustransferlist := bb.EnterComponent("BearersSubjectToEarlyStatusTransferList")
	v.BearersSubjectToEarlyStatusTransferList = make(s15.BearersSubjectToEarlyStatusTransferList, 0)
	_, errCollection_bearerssubjecttoearlystatustransferlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1) || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1)-fragmentLength_bearerssubjecttoearlystatustransferlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bearerssubjecttoearlystatustransferlist; i++ {
			var elem s15.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_bearerssubjecttoearlystatustransferlist + i)
			if err := s15.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BearersSubjectToEarlyStatusTransferList[%d]", fragmentOffset_bearerssubjecttoearlystatustransferlist+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.BearersSubjectToEarlyStatusTransferList, elem); err != nil {
				return err
			} else {
				v.BearersSubjectToEarlyStatusTransferList = next
			}
		}
		return nil
	})
	if errCollection_bearerssubjecttoearlystatustransferlist != nil {
		return runtime.WrapDecodePath(errCollection_bearerssubjecttoearlystatustransferlist, "BearersSubjectToEarlyStatusTransferList")
	}
	bb.LeaveComponent(toleranceMark_bearerssubjecttoearlystatustransferlist)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ENBEarlyStatusTransferTransparentContainerExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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

// MarshalAPER encodes UESidelinkAggregateMaximumBitrate to APER format.
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.UESidelinkAggregateMaximumBitRate), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uESidelinkAggregateMaximumBitRate: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESidelinkAggregateMaximumBitrate from APER format.
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UESidelinkAggregateMaximumBitrate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	bb.EnterComponent("UESidelinkAggregateMaximumBitrate")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	padding, err := aper.CaptureFinalBits(bb, "UESidelinkAggregateMaximumBitrate")
	if err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESidelinkAggregateMaximumBitrate{}
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
	val_uesidelinkaggregatemaximumbitrate, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitRate")
	}
	v.UESidelinkAggregateMaximumBitRate = s00.BitRate(val_uesidelinkaggregatemaximumbitrate)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ULCPSecurityInformation to APER format.
func (v *ULCPSecurityInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ULCPSecurityInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAligned(bb, v.UlNASMAC.Bytes, v.UlNASMAC.BitLength, 16, 16, true); err != nil {
		return fmt.Errorf("encoding ul-NAS-MAC: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.UlNASCount.Bytes, v.UlNASCount.BitLength, 5, 5, true); err != nil {
		return fmt.Errorf("encoding ul-NAS-Count: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ULCPSecurityInformation from APER format.
func (v *ULCPSecurityInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ULCPSecurityInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ULCPSecurityInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	bb.EnterComponent("ULCPSecurityInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "ULCPSecurityInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "ULCPSecurityInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ULCPSecurityInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ULCPSecurityInformation{}
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
	bsBytes_ulnasmac, bsBitLen_ulnasmac, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlNASMAC")
	}
	v.UlNASMAC = runtime.BitString{Bytes: bsBytes_ulnasmac, BitLength: bsBitLen_ulnasmac}
	bsBytes_ulnascount, bsBitLen_ulnascount, err := aper.DecodeBitStringAligned(bb, 5, 5, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UlNASCount")
	}
	v.UlNASCount = runtime.BitString{Bytes: bsBytes_ulnascount, BitLength: bsBitLen_ulnascount}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.ULCPSecurityInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.ULCPSecurityInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *BPLMNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BPLMNsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BPLMNsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BPLMNsComplete) WithoutReplay() BPLMNsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BPLMNsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToDLDiscardingListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToDLDiscardingListComplete) WithoutReplay() BearersSubjectToDLDiscardingListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToDLDiscardingListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToEarlyStatusTransferListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToEarlyStatusTransferListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToEarlyStatusTransferListComplete) WithoutReplay() BearersSubjectToEarlyStatusTransferListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToEarlyStatusTransferListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BearersSubjectToStatusTransferListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToStatusTransferListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BearersSubjectToStatusTransferListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BearersSubjectToStatusTransferListComplete) WithoutReplay() BearersSubjectToStatusTransferListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BearersSubjectToStatusTransferListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *BluetoothMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "BluetoothMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "BluetoothMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v BluetoothMeasConfigNameListComplete) WithoutReplay() BluetoothMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero BluetoothMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CNTypeRestrictionsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CNTypeRestrictionsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CNTypeRestrictionsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CNTypeRestrictionsComplete) WithoutReplay() CNTypeRestrictionsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CNTypeRestrictionsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CSGIdListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CSGIdListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CSGIdListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CSGIdListComplete) WithoutReplay() CSGIdListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CSGIdListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinEAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinEAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinEAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinEAIComplete) WithoutReplay() CancelledCellinEAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinEAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CancelledCellinTAIComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CancelledCellinTAIComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CancelledCellinTAIComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CancelledCellinTAIComplete) WithoutReplay() CancelledCellinTAIComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CancelledCellinTAIComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDBroadcastComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDBroadcastComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDBroadcastComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDBroadcastComplete) WithoutReplay() CellIDBroadcastComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDBroadcastComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIDCancelledComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIDCancelledComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIDCancelledComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIDCancelledComplete) WithoutReplay() CellIDCancelledComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIDCancelledComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIdListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIdListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIdListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIdListforMDTComplete) WithoutReplay() CellIdListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIdListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CellIdListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CellIdListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellIdListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellIdListforQMCComplete) WithoutReplay() CellIdListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellIdListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBEarlyStatusTransferTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBEarlyStatusTransferTransparentContainer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBEarlyStatusTransferTransparentContainer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBEarlyStatusTransferTransparentContainer) WithoutReplay() ENBEarlyStatusTransferTransparentContainer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBEarlyStatusTransferTransparentContainer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UESidelinkAggregateMaximumBitrate) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESidelinkAggregateMaximumBitrate", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UESidelinkAggregateMaximumBitrate", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UESidelinkAggregateMaximumBitrate) WithoutReplay() UESidelinkAggregateMaximumBitrate {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UESidelinkAggregateMaximumBitrate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULCPSecurityInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ULCPSecurityInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ULCPSecurityInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULCPSecurityInformation) WithoutReplay() ULCPSecurityInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ULCPSecurityInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBEarlyStatusTransferTransparentContainer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBEarlyStatusTransferTransparentContainer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBEarlyStatusTransferTransparentContainer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransferTransparentContainer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UESidelinkAggregateMaximumBitrate) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UESidelinkAggregateMaximumBitrate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UESidelinkAggregateMaximumBitrate) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESidelinkAggregateMaximumBitrate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ULCPSecurityInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ULCPSecurityInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ULCPSecurityInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ULCPSecurityInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BPLMNsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BPLMNsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BPLMNsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BPLMNsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBPLMNsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BPLMNsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BPLMNsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BPLMNsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BPLMNsComplete")
}
func (v *BPLMNsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BPLMNsComplete")
}
func (v *BPLMNsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBPLMNsComplete(v, &s)
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
func (v *BPLMNsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BPLMNsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERBPLMNsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToDLDiscardingListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToDLDiscardingListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v, &s)
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
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToEarlyStatusTransferListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToEarlyStatusTransferListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToEarlyStatusTransferListComplete(v, &s)
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
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToEarlyStatusTransferListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERBearersSubjectToEarlyStatusTransferListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BearersSubjectToStatusTransferListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BearersSubjectToStatusTransferListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBearersSubjectToStatusTransferListComplete(v, &s)
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
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BearersSubjectToStatusTransferListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERBearersSubjectToStatusTransferListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *BluetoothMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasConfigNameListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APBluetoothMeasConfigNameListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "BluetoothMeasConfigNameListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APBluetoothMeasConfigNameListComplete(v, &s)
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
func (v *BluetoothMeasConfigNameListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *BluetoothMeasConfigNameListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERBluetoothMeasConfigNameListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CNTypeRestrictionsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CNTypeRestrictionsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CNTypeRestrictionsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCNTypeRestrictionsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CNTypeRestrictionsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CNTypeRestrictionsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
}
func (v *CNTypeRestrictionsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CNTypeRestrictionsComplete")
}
func (v *CNTypeRestrictionsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCNTypeRestrictionsComplete(v, &s)
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
func (v *CNTypeRestrictionsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CNTypeRestrictionsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCNTypeRestrictionsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CSGIdListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CSGIdListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CSGIdListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CSGIdListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCSGIdListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CSGIdListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CSGIdListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CSGIdListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CSGIdListComplete")
}
func (v *CSGIdListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CSGIdListComplete")
}
func (v *CSGIdListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCSGIdListComplete(v, &s)
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
func (v *CSGIdListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CSGIdListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCSGIdListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CancelledCellinEAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinEAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinEAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinEAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinEAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinEAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinEAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinEAIComplete")
}
func (v *CancelledCellinEAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinEAIComplete")
}
func (v *CancelledCellinEAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinEAIComplete(v, &s)
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
func (v *CancelledCellinEAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinEAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCancelledCellinEAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CancelledCellinTAIComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CancelledCellinTAIComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CancelledCellinTAIComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCancelledCellinTAIComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CancelledCellinTAIComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CancelledCellinTAIComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CancelledCellinTAIComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CancelledCellinTAIComplete")
}
func (v *CancelledCellinTAIComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CancelledCellinTAIComplete")
}
func (v *CancelledCellinTAIComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCancelledCellinTAIComplete(v, &s)
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
func (v *CancelledCellinTAIComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CancelledCellinTAIComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCancelledCellinTAITo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIDBroadcastComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDBroadcastComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDBroadcastComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDBroadcastComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDBroadcastComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDBroadcastComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDBroadcastComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDBroadcastComplete")
}
func (v *CellIDBroadcastComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDBroadcastComplete")
}
func (v *CellIDBroadcastComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDBroadcastComplete(v, &s)
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
func (v *CellIDBroadcastComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDBroadcastComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCellIDBroadcastTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIDCancelledComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIDCancelledComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIDCancelledComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIDCancelledComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIDCancelledComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIDCancelledComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIDCancelledComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIDCancelledComplete")
}
func (v *CellIDCancelledComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIDCancelledComplete")
}
func (v *CellIDCancelledComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIDCancelledComplete(v, &s)
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
func (v *CellIDCancelledComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIDCancelledComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCellIDCancelledTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIdListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIdListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIdListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIdListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIdListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIdListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIdListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIdListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIdListforMDTComplete")
}
func (v *CellIdListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIdListforMDTComplete")
}
func (v *CellIdListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIdListforMDTComplete(v, &s)
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
func (v *CellIdListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIdListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCellIdListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CellIdListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellIdListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CellIdListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellIdListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCellIdListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CellIdListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CellIdListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CellIdListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CellIdListforQMCComplete")
}
func (v *CellIdListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CellIdListforQMCComplete")
}
func (v *CellIdListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCellIdListforQMCComplete(v, &s)
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
func (v *CellIdListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CellIdListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCellIdListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBEarlyStatusTransferTransparentContainer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransferTransparentContainer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBEarlyStatusTransferTransparentContainer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(v, &s)
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
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBEarlyStatusTransferTransparentContainer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UESidelinkAggregateMaximumBitrate) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UESidelinkAggregateMaximumBitrate")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UESidelinkAggregateMaximumBitrate")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v, &s)
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
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UESidelinkAggregateMaximumBitrate) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ULCPSecurityInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ULCPSecurityInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ULCPSecurityInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ULCPSecurityInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APULCPSecurityInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ULCPSecurityInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ULCPSecurityInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ULCPSecurityInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ULCPSecurityInformation")
}
func (v *ULCPSecurityInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ULCPSecurityInformation")
}
func (v *ULCPSecurityInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APULCPSecurityInformation(v, &s)
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
func (v *ULCPSecurityInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ULCPSecurityInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *BPLMNsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BPLMNsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BPLMNsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBPLMNsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BPLMNsComplete{}
		return report, aper.OperationError(err, "BPLMNsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BPLMNsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToDLDiscardingListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToDLDiscardingListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToDLDiscardingListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToDLDiscardingListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToDLDiscardingListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToDLDiscardingListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToDLDiscardingListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToEarlyStatusTransferListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToEarlyStatusTransferListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToEarlyStatusTransferListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToEarlyStatusTransferListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToEarlyStatusTransferListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToEarlyStatusTransferListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BearersSubjectToStatusTransferListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BearersSubjectToStatusTransferListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BearersSubjectToStatusTransferListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBearersSubjectToStatusTransferListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BearersSubjectToStatusTransferListComplete{}
		return report, aper.OperationError(err, "BearersSubjectToStatusTransferListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BearersSubjectToStatusTransferListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *BluetoothMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "BluetoothMeasConfigNameListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded BluetoothMeasConfigNameListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APBluetoothMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = BluetoothMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "BluetoothMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "BluetoothMeasConfigNameListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CNTypeRestrictionsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CNTypeRestrictionsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CNTypeRestrictionsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCNTypeRestrictionsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CNTypeRestrictionsComplete{}
		return report, aper.OperationError(err, "CNTypeRestrictionsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CNTypeRestrictionsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CSGIdListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CSGIdListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CSGIdListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCSGIdListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CSGIdListComplete{}
		return report, aper.OperationError(err, "CSGIdListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CSGIdListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinEAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinEAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinEAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinEAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinEAIComplete{}
		return report, aper.OperationError(err, "CancelledCellinEAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinEAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CancelledCellinTAIComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CancelledCellinTAIComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CancelledCellinTAIComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCancelledCellinTAIComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CancelledCellinTAIComplete{}
		return report, aper.OperationError(err, "CancelledCellinTAIComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CancelledCellinTAIComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDBroadcastComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDBroadcastComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDBroadcastComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDBroadcastComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDBroadcastComplete{}
		return report, aper.OperationError(err, "CellIDBroadcastComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDBroadcastComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIDCancelledComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIDCancelledComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIDCancelledComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIDCancelledComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIDCancelledComplete{}
		return report, aper.OperationError(err, "CellIDCancelledComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIDCancelledComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIdListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIdListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIdListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIdListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIdListforMDTComplete{}
		return report, aper.OperationError(err, "CellIdListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIdListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CellIdListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellIdListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CellIdListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCellIdListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CellIdListforQMCComplete{}
		return report, aper.OperationError(err, "CellIdListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellIdListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBEarlyStatusTransferTransparentContainer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransferTransparentContainer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBEarlyStatusTransferTransparentContainer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBEarlyStatusTransferTransparentContainer{}
		return report, aper.OperationError(err, "ENBEarlyStatusTransferTransparentContainer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBEarlyStatusTransferTransparentContainer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UESidelinkAggregateMaximumBitrate) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UESidelinkAggregateMaximumBitrate")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UESidelinkAggregateMaximumBitrate
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UESidelinkAggregateMaximumBitrate{}
		return report, aper.OperationError(err, "UESidelinkAggregateMaximumBitrate")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UESidelinkAggregateMaximumBitrate")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ULCPSecurityInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ULCPSecurityInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ULCPSecurityInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APULCPSecurityInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ULCPSecurityInformation{}
		return report, aper.OperationError(err, "ULCPSecurityInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ULCPSecurityInformation")
}

// MarshalAPERBearersSubjectToStatusTransferList encodes a complete named list.
func MarshalAPERBearersSubjectToStatusTransferList(v BearersSubjectToStatusTransferListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBearersSubjectToEarlyStatusTransferList encodes a complete named list.
func MarshalAPERBearersSubjectToEarlyStatusTransferList(v BearersSubjectToEarlyStatusTransferListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBearersSubjectToDLDiscardingList encodes a complete named list.
func MarshalAPERBearersSubjectToDLDiscardingList(v BearersSubjectToDLDiscardingListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBluetoothMeasConfigNameList encodes a complete named list.
func MarshalAPERBluetoothMeasConfigNameList(v BluetoothMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBPLMNs encodes a complete named list.
func MarshalAPERBPLMNs(v BPLMNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCancelledCellinEAI encodes a complete named list.
func MarshalAPERCancelledCellinEAI(v CancelledCellinEAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCancelledCellinTAI encodes a complete named list.
func MarshalAPERCancelledCellinTAI(v CancelledCellinTAIComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIDBroadcast encodes a complete named list.
func MarshalAPERCellIDBroadcast(v CellIDBroadcastComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIDCancelled encodes a complete named list.
func MarshalAPERCellIDCancelled(v CellIDCancelledComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCellIdListforMDT encodes a complete named list.
func MarshalAPERCellIdListforMDT(v CellIdListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCNTypeRestrictions encodes a complete named list.
func MarshalAPERCNTypeRestrictions(v CNTypeRestrictionsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCSGIdList encodes a complete named list.
func MarshalAPERCSGIdList(v CSGIdListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERBearersSubjectToStatusTransferList decodes a complete named list.
func UnmarshalAPERBearersSubjectToStatusTransferList(data []byte, options ...aper.DecodeOption) (BearersSubjectToStatusTransferListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToStatusTransferListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBearersSubjectToEarlyStatusTransferList decodes a complete named list.
func UnmarshalAPERBearersSubjectToEarlyStatusTransferList(data []byte, options ...aper.DecodeOption) (BearersSubjectToEarlyStatusTransferListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToEarlyStatusTransferListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBearersSubjectToDLDiscardingList decodes a complete named list.
func UnmarshalAPERBearersSubjectToDLDiscardingList(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToDLDiscardingListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBluetoothMeasConfigNameList decodes a complete named list.
func UnmarshalAPERBluetoothMeasConfigNameList(data []byte, options ...aper.DecodeOption) (BluetoothMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v BluetoothMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBPLMNs decodes a complete named list.
func UnmarshalAPERBPLMNs(data []byte, options ...aper.DecodeOption) (BPLMNsComplete, aper.DecodeReport, error) {
	var v BPLMNsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCancelledCellinEAI decodes a complete named list.
func UnmarshalAPERCancelledCellinEAI(data []byte, options ...aper.DecodeOption) (CancelledCellinEAIComplete, aper.DecodeReport, error) {
	var v CancelledCellinEAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCancelledCellinTAI decodes a complete named list.
func UnmarshalAPERCancelledCellinTAI(data []byte, options ...aper.DecodeOption) (CancelledCellinTAIComplete, aper.DecodeReport, error) {
	var v CancelledCellinTAIComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIDBroadcast decodes a complete named list.
func UnmarshalAPERCellIDBroadcast(data []byte, options ...aper.DecodeOption) (CellIDBroadcastComplete, aper.DecodeReport, error) {
	var v CellIDBroadcastComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIDCancelled decodes a complete named list.
func UnmarshalAPERCellIDCancelled(data []byte, options ...aper.DecodeOption) (CellIDCancelledComplete, aper.DecodeReport, error) {
	var v CellIDCancelledComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCellIdListforMDT decodes a complete named list.
func UnmarshalAPERCellIdListforMDT(data []byte, options ...aper.DecodeOption) (CellIdListforMDTComplete, aper.DecodeReport, error) {
	var v CellIdListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCNTypeRestrictions decodes a complete named list.
func UnmarshalAPERCNTypeRestrictions(data []byte, options ...aper.DecodeOption) (CNTypeRestrictionsComplete, aper.DecodeReport, error) {
	var v CNTypeRestrictionsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCSGIdList decodes a complete named list.
func UnmarshalAPERCSGIdList(data []byte, options ...aper.DecodeOption) (CSGIdListComplete, aper.DecodeReport, error) {
	var v CSGIdListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// ENBEarlyStatusTransfer represents the ASN.1 type ENBEarlyStatusTransfer (SEQUENCE).
type ENBEarlyStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ENBEarlyStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MMEEarlyStatusTransfer represents the ASN.1 type MMEEarlyStatusTransfer (SEQUENCE).
type MMEEarlyStatusTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      MMEEarlyStatusTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBCPRelocationIndication represents the ASN.1 type ENBCPRelocationIndication (SEQUENCE).
type ENBCPRelocationIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ENBCPRelocationIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ENBEarlyStatusTransfer to APER format.
func (v *ENBEarlyStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBEarlyStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ENBEarlyStatusTransfer from APER format.
func (v *ENBEarlyStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBEarlyStatusTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBEarlyStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransfer")
	}
	bb.EnterComponent("ENBEarlyStatusTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBEarlyStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBEarlyStatusTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBEarlyStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBEarlyStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ENBEarlyStatusTransferIEField
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

// MarshalAPER encodes MMEEarlyStatusTransfer to APER format.
func (v *MMEEarlyStatusTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MMEEarlyStatusTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes MMEEarlyStatusTransfer from APER format.
func (v *MMEEarlyStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MMEEarlyStatusTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MMEEarlyStatusTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	bb.EnterComponent("MMEEarlyStatusTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "MMEEarlyStatusTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEEarlyStatusTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MMEEarlyStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEEarlyStatusTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(MMEEarlyStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem MMEEarlyStatusTransferIEField
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

// MarshalAPER encodes ENBCPRelocationIndication to APER format.
func (v *ENBCPRelocationIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENBCPRelocationIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ENBCPRelocationIndication from APER format.
func (v *ENBCPRelocationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBCPRelocationIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENBCPRelocationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	bb.EnterComponent("ENBCPRelocationIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBCPRelocationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBCPRelocationIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENBCPRelocationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBCPRelocationIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBCPRelocationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ENBCPRelocationIndicationIEField
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
func (v *ENBCPRelocationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBCPRelocationIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBCPRelocationIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBCPRelocationIndication) WithoutReplay() ENBCPRelocationIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBCPRelocationIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBEarlyStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBEarlyStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBEarlyStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBEarlyStatusTransfer) WithoutReplay() ENBEarlyStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBEarlyStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MMEEarlyStatusTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "MMEEarlyStatusTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MMEEarlyStatusTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MMEEarlyStatusTransfer) WithoutReplay() MMEEarlyStatusTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MMEEarlyStatusTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ENBCPRelocationIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBCPRelocationIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBCPRelocationIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBCPRelocationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBEarlyStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBEarlyStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBEarlyStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MMEEarlyStatusTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MMEEarlyStatusTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MMEEarlyStatusTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MMEEarlyStatusTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ENBCPRelocationIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBCPRelocationIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBCPRelocationIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBCPRelocationIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBCPRelocationIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBCPRelocationIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBCPRelocationIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBCPRelocationIndication")
}
func (v *ENBCPRelocationIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBCPRelocationIndication")
}
func (v *ENBCPRelocationIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBCPRelocationIndication(v, &s)
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
func (v *ENBCPRelocationIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBCPRelocationIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBEarlyStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENBEarlyStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENBEarlyStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENBEarlyStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENBEarlyStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENBEarlyStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENBEarlyStatusTransfer")
}
func (v *ENBEarlyStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENBEarlyStatusTransfer")
}
func (v *ENBEarlyStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENBEarlyStatusTransfer(v, &s)
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
func (v *ENBEarlyStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENBEarlyStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *MMEEarlyStatusTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *MMEEarlyStatusTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MMEEarlyStatusTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APMMEEarlyStatusTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "MMEEarlyStatusTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *MMEEarlyStatusTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func (v *MMEEarlyStatusTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func (v *MMEEarlyStatusTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APMMEEarlyStatusTransfer(v, &s)
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
func (v *MMEEarlyStatusTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *MMEEarlyStatusTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENBCPRelocationIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBCPRelocationIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBCPRelocationIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBCPRelocationIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBCPRelocationIndication{}
		return report, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBCPRelocationIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ENBEarlyStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBEarlyStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENBEarlyStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENBEarlyStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENBEarlyStatusTransfer{}
		return report, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBEarlyStatusTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *MMEEarlyStatusTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MMEEarlyStatusTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded MMEEarlyStatusTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APMMEEarlyStatusTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = MMEEarlyStatusTransfer{}
		return report, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MMEEarlyStatusTransfer")
}

// CandidateCellListComplete carries a complete CandidateCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidateCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s18.CandidateCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CandidateCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCandidateCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CandidateCellList from APER format.
func (v *CandidateCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CandidateCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidateCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	bb.EnterComponent("CandidateCellList")
	value, err := BridgeUnmarshalAPERCandidateCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidateCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidateCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCandidateCellList encodes a CandidateCellList list to APER.
func BridgeMarshalAPERCandidateCellList(list CandidateCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCandidateCellList decodes a CandidateCellList list from APER.
func BridgeUnmarshalAPERCandidateCellList(data []byte) (CandidateCellListComplete, error) {
	var value CandidateCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCandidateCellListFrom decodes a CandidateCellList list from bb.
func BridgeUnmarshalAPERCandidateCellListFrom(bb *aper.BitBuffer) (s18.CandidateCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCandidateCellListListValue
	if err := BridgeUnmarshalAPERCandidateCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCandidateCellListInto(v *s21.BridgeAsn1cAPERCandidateCellListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s18.CandidateCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.IRATCellID
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CandidatePCIListComplete carries a complete CandidatePCIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CandidatePCIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s14.CandidatePCIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *CandidatePCIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERCandidatePCIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CandidatePCIList from APER format.
func (v *CandidatePCIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CandidatePCIList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CandidatePCIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	bb.EnterComponent("CandidatePCIList")
	value, err := BridgeUnmarshalAPERCandidatePCIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "CandidatePCIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "CandidatePCIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCandidatePCIList encodes a CandidatePCIList list to APER.
func BridgeMarshalAPERCandidatePCIList(list CandidatePCIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCandidatePCIList decodes a CandidatePCIList list from APER.
func BridgeUnmarshalAPERCandidatePCIList(data []byte) (CandidatePCIListComplete, error) {
	var value CandidatePCIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCandidatePCIListFrom decodes a CandidatePCIList list from bb.
func BridgeUnmarshalAPERCandidatePCIListFrom(bb *aper.BitBuffer) (s14.CandidatePCIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERCandidatePCIListListValue
	if err := BridgeUnmarshalAPERCandidatePCIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCandidatePCIListInto(v *s21.BridgeAsn1cAPERCandidatePCIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.CandidatePCIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.CandidatePCI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeCandidatePCIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ActivatedCellsListComplete carries a complete ActivatedCellsList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ActivatedCellsListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s14.ActivatedCellsList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ActivatedCellsListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ActivatedCellsList from APER format.
func (v *ActivatedCellsListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ActivatedCellsList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ActivatedCellsListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	bb.EnterComponent("ActivatedCellsList")
	value, err := BridgeUnmarshalAPERActivatedCellsListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ActivatedCellsList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ActivatedCellsList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERActivatedCellsList encodes a ActivatedCellsList list to APER.
func BridgeMarshalAPERActivatedCellsList(list ActivatedCellsListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERActivatedCellsList decodes a ActivatedCellsList list from APER.
func BridgeUnmarshalAPERActivatedCellsList(data []byte) (ActivatedCellsListComplete, error) {
	var value ActivatedCellsListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERActivatedCellsListFrom decodes a ActivatedCellsList list from bb.
func BridgeUnmarshalAPERActivatedCellsListFrom(bb *aper.BitBuffer) (s14.ActivatedCellsList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERActivatedCellsListListValue
	if err := BridgeUnmarshalAPERActivatedCellsListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERActivatedCellsListInto(v *s21.BridgeAsn1cAPERActivatedCellsListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.ActivatedCellsList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ActivatedCellsListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ActivatedCellsListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ActivatedCellsListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ActivatedCellsListComplete) WithoutReplay() ActivatedCellsListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ActivatedCellsListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CandidateCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidateCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidateCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidateCellListComplete) WithoutReplay() CandidateCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidateCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CandidatePCIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "CandidatePCIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CandidatePCIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CandidatePCIListComplete) WithoutReplay() CandidatePCIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CandidatePCIListComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ActivatedCellsListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ActivatedCellsListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ActivatedCellsListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APActivatedCellsListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ActivatedCellsListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ActivatedCellsListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ActivatedCellsListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ActivatedCellsListComplete")
}
func (v *ActivatedCellsListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ActivatedCellsListComplete")
}
func (v *ActivatedCellsListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APActivatedCellsListComplete(v, &s)
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
func (v *ActivatedCellsListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ActivatedCellsListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CandidateCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidateCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidateCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidateCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidateCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidateCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidateCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidateCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidateCellListComplete")
}
func (v *CandidateCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidateCellListComplete")
}
func (v *CandidateCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidateCellListComplete(v, &s)
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
func (v *CandidateCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidateCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCandidateCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *CandidatePCIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CandidatePCIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *CandidatePCIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CandidatePCIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APCandidatePCIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "CandidatePCIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "CandidatePCIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *CandidatePCIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "CandidatePCIListComplete")
}
func (v *CandidatePCIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "CandidatePCIListComplete")
}
func (v *CandidatePCIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APCandidatePCIListComplete(v, &s)
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
func (v *CandidatePCIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *CandidatePCIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERCandidatePCIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ActivatedCellsListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ActivatedCellsListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ActivatedCellsListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APActivatedCellsListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ActivatedCellsListComplete{}
		return report, aper.OperationError(err, "ActivatedCellsListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ActivatedCellsListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CandidateCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidateCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidateCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidateCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidateCellListComplete{}
		return report, aper.OperationError(err, "CandidateCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidateCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *CandidatePCIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CandidatePCIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded CandidatePCIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APCandidatePCIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = CandidatePCIListComplete{}
		return report, aper.OperationError(err, "CandidatePCIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CandidatePCIListComplete")
}

// MarshalAPERCandidateCellList encodes a complete named list.
func MarshalAPERCandidateCellList(v CandidateCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCandidatePCIList encodes a complete named list.
func MarshalAPERCandidatePCIList(v CandidatePCIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERActivatedCellsList encodes a complete named list.
func MarshalAPERActivatedCellsList(v ActivatedCellsListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERCandidateCellList decodes a complete named list.
func UnmarshalAPERCandidateCellList(data []byte, options ...aper.DecodeOption) (CandidateCellListComplete, aper.DecodeReport, error) {
	var v CandidateCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCandidatePCIList decodes a complete named list.
func UnmarshalAPERCandidatePCIList(data []byte, options ...aper.DecodeOption) (CandidatePCIListComplete, aper.DecodeReport, error) {
	var v CandidatePCIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERActivatedCellsList decodes a complete named list.
func UnmarshalAPERActivatedCellsList(data []byte, options ...aper.DecodeOption) (ActivatedCellsListComplete, aper.DecodeReport, error) {
	var v ActivatedCellsListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type ENBEarlyStatusTransferTransparentContainerExtIEsValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowBearersSubjectToDLDiscardingList *s15.BearersSubjectToDLDiscardingList
}

func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(352):
		return v.rowBearersSubjectToDLDiscardingList != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBEarlyStatusTransferTransparentContainerExtIEsValue and reports whether the opaque alternative is selected.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBEarlyStatusTransferTransparentContainerExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"}}
}
func (ENBEarlyStatusTransferTransparentContainerExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(352):
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

// AsBearersSubjectToDLDiscardingList returns the selected BearersSubjectToDLDiscardingList value of ENBEarlyStatusTransferTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) AsBearersSubjectToDLDiscardingList() (*s15.BearersSubjectToDLDiscardingList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(352) || v.rowBearersSubjectToDLDiscardingList == nil {
		return nil, false
	}
	return v.rowBearersSubjectToDLDiscardingList, true
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBEarlyStatusTransferTransparentContainerExtIEsValue, error) {
	out := ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(352):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "BearersSubjectToDLDiscardingList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowBearersSubjectToDLDiscardingList = &value
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
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ENBEarlyStatusTransferTransparentContainerExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(352):
		if v.rowBearersSubjectToDLDiscardingList == nil {
			return nil, fmt.Errorf("%s missing value", "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs.id-Bearers-SubjectToDLDiscardingList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := BearersSubjectToDLDiscardingListComplete{Value: *v.rowBearersSubjectToDLDiscardingList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBEarlyStatusTransferTransparentContainerExtIEsValue:", v.id)
	}
}

type ENBCPRelocationIndicationIEValue struct {
	id                         s00.ProtocolIEID
	received                   aper.WireSpan
	replay                     aper.Snapshot
	opaque                     aper.OpaqueOpenType
	isOpaque                   bool
	rowENBUES1APID             *s00.ENBUES1APID
	rowSTMSI                   *s28.STMSI
	rowEUTRANCGI               *s17.EUTRANCGI
	rowTAI                     *s32.TAI
	rowULCPSecurityInformation *ULCPSecurityInformation
	rowLTENTNTAIInformation    *s18.LTENTNTAIInformation
}

func (v ENBCPRelocationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(96):
		return v.rowSTMSI != nil
	case s00.ProtocolIEID(100):
		return v.rowEUTRANCGI != nil
	case s00.ProtocolIEID(67):
		return v.rowTAI != nil
	case s00.ProtocolIEID(254):
		return v.rowULCPSecurityInformation != nil
	case s00.ProtocolIEID(339):
		return v.rowLTENTNTAIInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBCPRelocationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *ENBCPRelocationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBCPRelocationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs"}}
}
func (ENBCPRelocationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(96):
		return aper.UnknownSelector
	case s00.ProtocolIEID(100):
		return aper.UnknownSelector
	case s00.ProtocolIEID(67):
		return aper.UnknownSelector
	case s00.ProtocolIEID(254):
		return aper.UnknownSelector
	case s00.ProtocolIEID(339):
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

// AsENBUES1APID returns the selected ENBUES1APID value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsSTMSI returns the selected STMSI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsSTMSI() (*s28.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsTAI() (*s32.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsULCPSecurityInformation returns the selected ULCPSecurityInformation value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsULCPSecurityInformation() (*ULCPSecurityInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(254) || v.rowULCPSecurityInformation == nil {
		return nil, false
	}
	return v.rowULCPSecurityInformation, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}
func (v ENBCPRelocationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue, error) {
	out := ENBCPRelocationIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(96):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s28.STMSI
		child := scope
		if err := s28.BridgeSTMSIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "STMSI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "STMSI")
		if err != nil {
			return out, err
		}
		*s28.BridgeSTMSIFieldPerPadding(&value) = padding
		*s28.BridgeSTMSIFieldReceived(&value) = true
		raw.RetainContents(s28.BridgeSTMSIFieldReceivedBytes(&value))
		*s28.BridgeSTMSIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSTMSI = &value
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
		var value s32.TAI
		child := scope
		if err := s32.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s32.BridgeTAIFieldPerPadding(&value) = padding
		*s32.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s32.BridgeTAIFieldReceivedBytes(&value))
		*s32.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(254):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ULCPSecurityInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ULCPSecurityInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ULCPSecurityInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowULCPSecurityInformation = &value
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
func (v ENBCPRelocationIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBCPRelocationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(96):
		if v.rowSTMSI == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-S-TMSI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s28.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(100):
		if v.rowEUTRANCGI == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-EUTRAN-CGI:")
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
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-TAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s32.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(254):
		if v.rowULCPSecurityInformation == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-UL-CP-SecurityInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowULCPSecurityInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(339):
		if v.rowLTENTNTAIInformation == nil {
			return nil, fmt.Errorf("%s missing value", "ENBCPRelocationIndicationIEs.id-LTE-NTN-TAI-Information:")
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
		return nil, fmt.Errorf("%s id %d has no value", "ENBCPRelocationIndicationIEValue:", v.id)
	}
}

type ENBEarlyStatusTransferIEValue struct {
	id                                            s00.ProtocolIEID
	received                                      aper.WireSpan
	replay                                        aper.Snapshot
	opaque                                        aper.OpaqueOpenType
	isOpaque                                      bool
	rowMMEUES1APID                                *s00.MMEUES1APID
	rowENBUES1APID                                *s00.ENBUES1APID
	rowENBEarlyStatusTransferTransparentContainer *ENBEarlyStatusTransferTransparentContainer
}

func (v ENBEarlyStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(321):
		return v.rowENBEarlyStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBEarlyStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBEarlyStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBEarlyStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs"}}
}
func (ENBEarlyStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(321):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBEarlyStatusTransferTransparentContainer returns the selected ENBEarlyStatusTransferTransparentContainer value of ENBEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *ENBEarlyStatusTransferIEValue) AsENBEarlyStatusTransferTransparentContainer() (*ENBEarlyStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(321) || v.rowENBEarlyStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBEarlyStatusTransferTransparentContainer, true
}
func (v ENBEarlyStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBEarlyStatusTransferIEValue, error) {
	out := ENBEarlyStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(321):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBEarlyStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBEarlyStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBEarlyStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBEarlyStatusTransferTransparentContainer = &value
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
func (v ENBEarlyStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBEarlyStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(321):
		if v.rowENBEarlyStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "ENBEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBEarlyStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBEarlyStatusTransferIEValue:", v.id)
	}
}

type MMEEarlyStatusTransferIEValue struct {
	id                                            s00.ProtocolIEID
	received                                      aper.WireSpan
	replay                                        aper.Snapshot
	opaque                                        aper.OpaqueOpenType
	isOpaque                                      bool
	rowMMEUES1APID                                *s00.MMEUES1APID
	rowENBUES1APID                                *s00.ENBUES1APID
	rowENBEarlyStatusTransferTransparentContainer *ENBEarlyStatusTransferTransparentContainer
}

func (v MMEEarlyStatusTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(321):
		return v.rowENBEarlyStatusTransferTransparentContainer != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEEarlyStatusTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEEarlyStatusTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEEarlyStatusTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs"}}
}
func (MMEEarlyStatusTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(321):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsENBEarlyStatusTransferTransparentContainer returns the selected ENBEarlyStatusTransferTransparentContainer value of MMEEarlyStatusTransferIEValue and reports whether that alternative is active.
func (v *MMEEarlyStatusTransferIEValue) AsENBEarlyStatusTransferTransparentContainer() (*ENBEarlyStatusTransferTransparentContainer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(321) || v.rowENBEarlyStatusTransferTransparentContainer == nil {
		return nil, false
	}
	return v.rowENBEarlyStatusTransferTransparentContainer, true
}
func (v MMEEarlyStatusTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEEarlyStatusTransferIEValue, error) {
	out := MMEEarlyStatusTransferIEValue{id: id}
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
	case s00.ProtocolIEID(321):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENBEarlyStatusTransferTransparentContainer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENBEarlyStatusTransferTransparentContainer:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBEarlyStatusTransferTransparentContainer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENBEarlyStatusTransferTransparentContainer = &value
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
func (v MMEEarlyStatusTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEEarlyStatusTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(321):
		if v.rowENBEarlyStatusTransferTransparentContainer == nil {
			return nil, fmt.Errorf("%s missing value", "MMEEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENBEarlyStatusTransferTransparentContainer.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEEarlyStatusTransferIEValue:", v.id)
	}
}

type ENBEarlyStatusTransferTransparentContainerExtIETable struct{}

func ENBEarlyStatusTransferTransparentContainerExtIEs() ENBEarlyStatusTransferTransparentContainerExtIETable {
	return ENBEarlyStatusTransferTransparentContainerExtIETable{}
}

// ID returns the ASN.1 object-set identity of ENBEarlyStatusTransferTransparentContainerExtIETable.
func (ENBEarlyStatusTransferTransparentContainerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBEarlyStatusTransferTransparentContainerExtIETable.
func (ENBEarlyStatusTransferTransparentContainerExtIETable) Table() s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable {
	return func() s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable {
		sealed := s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable{}
		*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBEarlyStatusTransferTransparentContainerExtIETable) infoBearersSubjectToDLDiscardingList() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: ENBEarlyStatusTransferTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(352), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscardingList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs", Row: "id-Bearers-SubjectToDLDiscardingList"}}}
}

// BearersSubjectToDLDiscardingList returns the typed binding for the BearersSubjectToDLDiscardingList row of ENBEarlyStatusTransferTransparentContainerExtIETable.
func (t ENBEarlyStatusTransferTransparentContainerExtIETable) BearersSubjectToDLDiscardingList() ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding {
	return ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding{info: t.infoBearersSubjectToDLDiscardingList(), codec: func() s15.BearersSubjectToDLDiscardingListValueCodec {
		sealed := s15.BearersSubjectToDLDiscardingListValueCodec{}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingList"
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToDLDiscardingList")
			var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(352), raw)
			if err != nil {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
			}
			value, ok := decoded.AsBearersSubjectToDLDiscardingList()
			if !ok {
				var empty s15.BearersSubjectToDLDiscardingList
				return empty, fmt.Errorf("binding ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs.id-Bearers-SubjectToDLDiscardingList: no selected value")
			}
			return *value, nil
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToDLDiscardingList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}).encodeFresh(fresh, budget)
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToDLDiscardingList, options aper.DecodeState) (s15.BearersSubjectToDLDiscardingList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToDLDiscardingList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeBearersSubjectToDLDiscardingListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToDLDiscardingList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s15.BearersSubjectToDLDiscardingList) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
			return ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}
		}, get: func(value *ENBEarlyStatusTransferTransparentContainerExtIEsValue) (*s15.BearersSubjectToDLDiscardingList, bool) {
			return value.AsBearersSubjectToDLDiscardingList()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBEarlyStatusTransferTransparentContainerExtIETable.
func (t ENBEarlyStatusTransferTransparentContainerExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(352):
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Bearers-SubjectToDLDiscardingList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBCPRelocationIndicationIETable struct{}

func ENBCPRelocationIndicationIEs() ENBCPRelocationIndicationIETable {
	return ENBCPRelocationIndicationIETable{}
}

// ID returns the ASN.1 object-set identity of ENBCPRelocationIndicationIETable.
func (ENBCPRelocationIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBCPRelocationIndicationIETable.
func (ENBCPRelocationIndicationIETable) Table() s00.ENBCPRelocationIndicationIEValueIETable {
	return func() s00.ENBCPRelocationIndicationIEValueIETable {
		sealed := s00.ENBCPRelocationIndicationIEValueIETable{}
		*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBCPRelocationIndicationIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) ENBUES1APID() ENBCPRelocationIndicationENBUES1APIDIEBinding {
	return ENBCPRelocationIndicationENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBCPRelocationIndicationIETable) infoSTMSI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(96), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "S-TMSI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-S-TMSI"}}}
}

// STMSI returns the typed binding for the STMSI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) STMSI() ENBCPRelocationIndicationSTMSIIEBinding {
	return ENBCPRelocationIndicationSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s28.STMSIValueCodec {
		sealed := s28.STMSIValueCodec{}
		*s28.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s28.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.STMSI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("STMSI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s28.STMSI
				return empty, runtime.WrapDecodePath(err, "STMSI")
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s28.STMSI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s28.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s28.STMSI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s28.STMSI, bool) { return value.AsSTMSI() }}
}
func (ENBCPRelocationIndicationIETable) infoEUTRANCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(100), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EUTRAN-CGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-EUTRAN-CGI"}}}
}

// EUTRANCGI returns the typed binding for the EUTRANCGI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) EUTRANCGI() ENBCPRelocationIndicationEUTRANCGIIEBinding {
	return ENBCPRelocationIndicationEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s18.EUTRANCGIValueCodec {
		sealed := s18.EUTRANCGIValueCodec{}
		*s18.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s18.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s17.EUTRANCGI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s17.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
}
func (ENBCPRelocationIndicationIETable) infoTAI() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(67), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-TAI"}}}
}

// TAI returns the typed binding for the TAI row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) TAI() ENBCPRelocationIndicationTAIIEBinding {
	return ENBCPRelocationIndicationTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s32.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s32.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s32.TAI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s32.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
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
	}(),
		inject: func(value s32.TAI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s32.TAI, bool) { return value.AsTAI() }}
}
func (ENBCPRelocationIndicationIETable) infoULCPSecurityInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(254), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UL-CP-SecurityInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-UL-CP-SecurityInformation"}}}
}

// ULCPSecurityInformation returns the typed binding for the ULCPSecurityInformation row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) ULCPSecurityInformation() ENBCPRelocationIndicationULCPSecurityInformationIEBinding {
	return ENBCPRelocationIndicationULCPSecurityInformationIEBinding{info: t.infoULCPSecurityInformation(), codec: ULCPSecurityInformationValueCodec{path: "ULCPSecurityInformation",
		decode: func(data []byte, options aper.DecodeState) (ULCPSecurityInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ULCPSecurityInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ULCPSecurityInformation")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(254), raw)
			if err != nil {
				var empty ULCPSecurityInformation
				return empty, runtime.WrapDecodePath(err, "ULCPSecurityInformation")
			}
			value, ok := decoded.AsULCPSecurityInformation()
			if !ok {
				var empty ULCPSecurityInformation
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-UL-CP-SecurityInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value ULCPSecurityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(254), rowULCPSecurityInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ULCPSecurityInformation, options aper.DecodeState) (ULCPSecurityInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APULCPSecurityInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v ULCPSecurityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APULCPSecurityInformation(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULCPSecurityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ULCPSecurityInformation) ENBCPRelocationIndicationIEValue {
		return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(254), rowULCPSecurityInformation: &value}
	}, get: func(value *ENBCPRelocationIndicationIEValue) (*ULCPSecurityInformation, bool) {
		return value.AsULCPSecurityInformation()
	}}
}
func (ENBCPRelocationIndicationIETable) infoLTENTNTAIInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBCPRelocationIndicationIEs().ID(), ID: s00.ProtocolIEID(339), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LTE-NTN-TAI-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBCPRelocationIndicationIEs", Row: "id-LTE-NTN-TAI-Information"}}}
}

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) LTENTNTAIInformation() ENBCPRelocationIndicationLTENTNTAIInformationIEBinding {
	return ENBCPRelocationIndicationLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s18.LTENTNTAIInformationValueCodec {
		sealed := s18.LTENTNTAIInformationValueCodec{}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s18.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s18.LTENTNTAIInformation
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s18.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.LTENTNTAIInformation) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s18.LTENTNTAIInformation, bool) {
			return value.AsLTENTNTAIInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBCPRelocationIndicationIETable.
func (t ENBCPRelocationIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBCPRelocationIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(8):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(96):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-S-TMSI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(100):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EUTRAN-CGI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(67):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(254):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-UL-CP-SecurityInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(339):
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-LTE-NTN-TAI-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBCPRelocationIndicationIEField{Id: id, Criticality: criticality, Value: ENBCPRelocationIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ENBEarlyStatusTransferIETable struct{}

func ENBEarlyStatusTransferIEs() ENBEarlyStatusTransferIETable {
	return ENBEarlyStatusTransferIETable{}
}

// ID returns the ASN.1 object-set identity of ENBEarlyStatusTransferIETable.
func (ENBEarlyStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ENBEarlyStatusTransferIETable.
func (ENBEarlyStatusTransferIETable) Table() s00.ENBEarlyStatusTransferIEValueIETable {
	return func() s00.ENBEarlyStatusTransferIEValueIETable {
		sealed := s00.ENBEarlyStatusTransferIEValueIETable{}
		*s00.BridgeENBEarlyStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ENBEarlyStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) MMEUES1APID() ENBEarlyStatusTransferMMEUES1APIDIEBinding {
	return ENBEarlyStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) ENBEarlyStatusTransferIEValue {
			return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *ENBEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (ENBEarlyStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) ENBUES1APID() ENBEarlyStatusTransferENBUES1APIDIEBinding {
	return ENBEarlyStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) ENBEarlyStatusTransferIEValue {
			return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *ENBEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (ENBEarlyStatusTransferIETable) infoENBEarlyStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: ENBEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(321), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBEarlyStatusTransferIEs", Row: "id-eNB-EarlyStatusTransfer-TransparentContainer"}}}
}

// ENBEarlyStatusTransferTransparentContainer returns the typed binding for the ENBEarlyStatusTransferTransparentContainer row of ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) ENBEarlyStatusTransferTransparentContainer() ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding {
	return ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding{info: t.infoENBEarlyStatusTransferTransparentContainer(), codec: ENBEarlyStatusTransferTransparentContainerValueCodec{path: "ENBEarlyStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBEarlyStatusTransferTransparentContainer")
			var zero ENBEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(321), raw)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBEarlyStatusTransferTransparentContainer()
			if !ok {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding ENBEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBEarlyStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBEarlyStatusTransferTransparentContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBEarlyStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBEarlyStatusTransferTransparentContainer) ENBEarlyStatusTransferIEValue {
		return ENBEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}
	}, get: func(value *ENBEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
		return value.AsENBEarlyStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ENBEarlyStatusTransferIETable.
func (t ENBEarlyStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ENBEarlyStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(321):
		return ENBEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-EarlyStatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ENBEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return ENBEarlyStatusTransferIEField{Id: id, Criticality: criticality, Value: ENBEarlyStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type MMEEarlyStatusTransferIETable struct{}

func MMEEarlyStatusTransferIEs() MMEEarlyStatusTransferIETable {
	return MMEEarlyStatusTransferIETable{}
}

// ID returns the ASN.1 object-set identity of MMEEarlyStatusTransferIETable.
func (MMEEarlyStatusTransferIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by MMEEarlyStatusTransferIETable.
func (MMEEarlyStatusTransferIETable) Table() s00.MMEEarlyStatusTransferIEValueIETable {
	return func() s00.MMEEarlyStatusTransferIEValueIETable {
		sealed := s00.MMEEarlyStatusTransferIEValueIETable{}
		*s00.BridgeMMEEarlyStatusTransferIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (MMEEarlyStatusTransferIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) MMEUES1APID() MMEEarlyStatusTransferMMEUES1APIDIEBinding {
	return MMEEarlyStatusTransferMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) MMEEarlyStatusTransferIEValue {
			return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *MMEEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (MMEEarlyStatusTransferIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) ENBUES1APID() MMEEarlyStatusTransferENBUES1APIDIEBinding {
	return MMEEarlyStatusTransferENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) MMEEarlyStatusTransferIEValue {
			return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *MMEEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (MMEEarlyStatusTransferIETable) infoENBEarlyStatusTransferTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: MMEEarlyStatusTransferIEs().ID(), ID: s00.ProtocolIEID(321), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-EarlyStatusTransfer-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEEarlyStatusTransferIEs", Row: "id-eNB-EarlyStatusTransfer-TransparentContainer"}}}
}

// ENBEarlyStatusTransferTransparentContainer returns the typed binding for the ENBEarlyStatusTransferTransparentContainer row of MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) ENBEarlyStatusTransferTransparentContainer() MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding {
	return MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding{info: t.infoENBEarlyStatusTransferTransparentContainer(), codec: ENBEarlyStatusTransferTransparentContainerValueCodec{path: "ENBEarlyStatusTransferTransparentContainer",
		decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBEarlyStatusTransferTransparentContainer")
			var zero MMEEarlyStatusTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(321), raw)
			if err != nil {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, runtime.WrapDecodePath(err, "ENBEarlyStatusTransferTransparentContainer")
			}
			value, ok := decoded.AsENBEarlyStatusTransferTransparentContainer()
			if !ok {
				var empty ENBEarlyStatusTransferTransparentContainer
				return empty, fmt.Errorf("binding MMEEarlyStatusTransferIEs.id-eNB-EarlyStatusTransfer-TransparentContainer: no selected value")
			}
			return *value, nil
		},
		encode: func(value ENBEarlyStatusTransferTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ENBEarlyStatusTransferTransparentContainer, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v ENBEarlyStatusTransferTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			BridgeCompareS1APENBEarlyStatusTransferTransparentContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBEarlyStatusTransferTransparentContainer"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value ENBEarlyStatusTransferTransparentContainer) MMEEarlyStatusTransferIEValue {
		return MMEEarlyStatusTransferIEValue{id: s00.ProtocolIEID(321), rowENBEarlyStatusTransferTransparentContainer: &value}
	}, get: func(value *MMEEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
		return value.AsENBEarlyStatusTransferTransparentContainer()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in MMEEarlyStatusTransferIETable.
func (t MMEEarlyStatusTransferIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (MMEEarlyStatusTransferIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(321):
		return MMEEarlyStatusTransferIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-EarlyStatusTransfer-TransparentContainer requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return MMEEarlyStatusTransferIEField{}, aper.OperationError(err, "Opaque")
		}
		return MMEEarlyStatusTransferIEField{Id: id, Criticality: criticality, Value: MMEEarlyStatusTransferIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ActivatedCellsListCodec binds the complete source value type.
func ActivatedCellsListCodec() s14.ActivatedCellsListValueCodec {
	return func() s14.ActivatedCellsListValueCodec {
		sealed := s14.ActivatedCellsListValueCodec{}
		*s14.BridgeActivatedCellsListValueCodecFieldPath(&sealed) = "ActivatedCellsList"
		*s14.BridgeActivatedCellsListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ActivatedCellsList, error) {
			var complete ActivatedCellsListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s14.ActivatedCellsList
				return zero, err
			}
			return complete.Value, nil
		}
		*s14.BridgeActivatedCellsListValueCodecFieldEncode(&sealed) = func(value s14.ActivatedCellsList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ActivatedCellsListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s14.BridgeActivatedCellsListValueCodecFieldCapture(&sealed) = func(v s14.ActivatedCellsList, options aper.DecodeState) (s14.ActivatedCellsList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APActivatedCellsList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s14.BridgeActivatedCellsListValueCodecFieldCompare(&sealed) = func(v s14.ActivatedCellsList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APActivatedCellsList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeActivatedCellsListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ActivatedCellsList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BPLMNsCodec binds the complete source value type.
func BPLMNsCodec() s00.BPLMNsValueCodec {
	return func() s00.BPLMNsValueCodec {
		sealed := s00.BPLMNsValueCodec{}
		*s00.BridgeBPLMNsValueCodecFieldPath(&sealed) = "BPLMNs"
		*s00.BridgeBPLMNsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BPLMNs, error) {
			var complete BPLMNsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.BPLMNs
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeBPLMNsValueCodecFieldEncode(&sealed) = func(value s00.BPLMNs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BPLMNsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeBPLMNsValueCodecFieldCapture(&sealed) = func(v s00.BPLMNs, options aper.DecodeState) (s00.BPLMNs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APBPLMNs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBPLMNsValueCodecFieldCompare(&sealed) = func(v s00.BPLMNs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APBPLMNs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBPLMNsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BPLMNs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToDLDiscardingListCodec binds the complete APER value type.
func BearersSubjectToDLDiscardingListCodec() s15.BearersSubjectToDLDiscardingListValueCodec {
	return ENBEarlyStatusTransferTransparentContainerExtIEs().BearersSubjectToDLDiscardingList().Codec()
}

// BearersSubjectToEarlyStatusTransferListCodec binds the complete source value type.
func BearersSubjectToEarlyStatusTransferListCodec() s15.BearersSubjectToEarlyStatusTransferListValueCodec {
	return func() s15.BearersSubjectToEarlyStatusTransferListValueCodec {
		sealed := s15.BearersSubjectToEarlyStatusTransferListValueCodec{}
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldPath(&sealed) = "BearersSubjectToEarlyStatusTransferList"
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferList, error) {
			var complete BearersSubjectToEarlyStatusTransferListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s15.BearersSubjectToEarlyStatusTransferList
				return zero, err
			}
			return complete.Value, nil
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldEncode(&sealed) = func(value s15.BearersSubjectToEarlyStatusTransferList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BearersSubjectToEarlyStatusTransferListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCapture(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferList, options aper.DecodeState) (s15.BearersSubjectToEarlyStatusTransferList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldCompare(&sealed) = func(v s15.BearersSubjectToEarlyStatusTransferList, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s15.BridgeBearersSubjectToEarlyStatusTransferListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToEarlyStatusTransferList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BearersSubjectToStatusTransferListCodec binds the complete source value type.
func BearersSubjectToStatusTransferListCodec() s21.BearersSubjectToStatusTransferListValueCodec {
	return func() s21.BearersSubjectToStatusTransferListValueCodec {
		sealed := s21.BearersSubjectToStatusTransferListValueCodec{}
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldPath(&sealed) = "BearersSubjectToStatusTransferList"
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.BearersSubjectToStatusTransferList, error) {
			var complete BearersSubjectToStatusTransferListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s21.BearersSubjectToStatusTransferList
				return zero, err
			}
			return complete.Value, nil
		}
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldEncode(&sealed) = func(value s21.BearersSubjectToStatusTransferList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BearersSubjectToStatusTransferListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldCapture(&sealed) = func(v s21.BearersSubjectToStatusTransferList, options aper.DecodeState) (s21.BearersSubjectToStatusTransferList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APBearersSubjectToStatusTransferList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldCompare(&sealed) = func(v s21.BearersSubjectToStatusTransferList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APBearersSubjectToStatusTransferList(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeBearersSubjectToStatusTransferListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToStatusTransferList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BluetoothMeasConfigNameListCodec binds the complete source value type.
func BluetoothMeasConfigNameListCodec() s00.BluetoothMeasConfigNameListValueCodec {
	return func() s00.BluetoothMeasConfigNameListValueCodec {
		sealed := s00.BluetoothMeasConfigNameListValueCodec{}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldPath(&sealed) = "BluetoothMeasConfigNameList"
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BluetoothMeasConfigNameList, error) {
			var complete BluetoothMeasConfigNameListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.BluetoothMeasConfigNameList
				return zero, err
			}
			return complete.Value, nil
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldEncode(&sealed) = func(value s00.BluetoothMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := BluetoothMeasConfigNameListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldCapture(&sealed) = func(v s00.BluetoothMeasConfigNameList, options aper.DecodeState) (s00.BluetoothMeasConfigNameList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APBluetoothMeasConfigNameList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldCompare(&sealed) = func(v s00.BluetoothMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s02.BridgeCompareS1APBluetoothMeasConfigNameList(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBluetoothMeasConfigNameListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothMeasConfigNameList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinEAICodec binds the complete source value type.
func CancelledCellinEAICodec() s17.CancelledCellinEAIValueCodec {
	return func() s17.CancelledCellinEAIValueCodec {
		sealed := s17.CancelledCellinEAIValueCodec{}
		*s17.BridgeCancelledCellinEAIValueCodecFieldPath(&sealed) = "CancelledCellinEAI"
		*s17.BridgeCancelledCellinEAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CancelledCellinEAI, error) {
			var complete CancelledCellinEAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CancelledCellinEAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCancelledCellinEAIValueCodecFieldEncode(&sealed) = func(value s17.CancelledCellinEAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CancelledCellinEAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCancelledCellinEAIValueCodecFieldCapture(&sealed) = func(v s17.CancelledCellinEAI, options aper.DecodeState) (s17.CancelledCellinEAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCancelledCellinEAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s17.BridgeCancelledCellinEAIValueCodecFieldCompare(&sealed) = func(v s17.CancelledCellinEAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCancelledCellinEAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCancelledCellinEAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinEAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CancelledCellinTAICodec binds the complete source value type.
func CancelledCellinTAICodec() s17.CancelledCellinTAIValueCodec {
	return func() s17.CancelledCellinTAIValueCodec {
		sealed := s17.CancelledCellinTAIValueCodec{}
		*s17.BridgeCancelledCellinTAIValueCodecFieldPath(&sealed) = "CancelledCellinTAI"
		*s17.BridgeCancelledCellinTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CancelledCellinTAI, error) {
			var complete CancelledCellinTAIComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CancelledCellinTAI
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCancelledCellinTAIValueCodecFieldEncode(&sealed) = func(value s17.CancelledCellinTAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CancelledCellinTAIComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCancelledCellinTAIValueCodecFieldCapture(&sealed) = func(v s17.CancelledCellinTAI, options aper.DecodeState) (s17.CancelledCellinTAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCancelledCellinTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s17.BridgeCancelledCellinTAIValueCodecFieldCompare(&sealed) = func(v s17.CancelledCellinTAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCancelledCellinTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCancelledCellinTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CancelledCellinTAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CandidateCellListCodec binds the complete source value type.
func CandidateCellListCodec() s18.CandidateCellListValueCodec {
	return func() s18.CandidateCellListValueCodec {
		sealed := s18.CandidateCellListValueCodec{}
		*s18.BridgeCandidateCellListValueCodecFieldPath(&sealed) = "CandidateCellList"
		*s18.BridgeCandidateCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.CandidateCellList, error) {
			var complete CandidateCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s18.CandidateCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s18.BridgeCandidateCellListValueCodecFieldEncode(&sealed) = func(value s18.CandidateCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CandidateCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s18.BridgeCandidateCellListValueCodecFieldCapture(&sealed) = func(v s18.CandidateCellList, options aper.DecodeState) (s18.CandidateCellList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCandidateCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s18.BridgeCandidateCellListValueCodecFieldCompare(&sealed) = func(v s18.CandidateCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCandidateCellList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s18.BridgeCandidateCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidateCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CandidatePCIListCodec binds the complete source value type.
func CandidatePCIListCodec() s14.CandidatePCIListValueCodec {
	return func() s14.CandidatePCIListValueCodec {
		sealed := s14.CandidatePCIListValueCodec{}
		*s14.BridgeCandidatePCIListValueCodecFieldPath(&sealed) = "CandidatePCIList"
		*s14.BridgeCandidatePCIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CandidatePCIList, error) {
			var complete CandidatePCIListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s14.CandidatePCIList
				return zero, err
			}
			return complete.Value, nil
		}
		*s14.BridgeCandidatePCIListValueCodecFieldEncode(&sealed) = func(value s14.CandidatePCIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CandidatePCIListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s14.BridgeCandidatePCIListValueCodecFieldCapture(&sealed) = func(v s14.CandidatePCIList, options aper.DecodeState) (s14.CandidatePCIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s21.BridgeCaptureS1APCandidatePCIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeCandidatePCIListValueCodecFieldCompare(&sealed) = func(v s14.CandidatePCIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCandidatePCIList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s14.BridgeCandidatePCIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CandidatePCIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDBroadcastCodec binds the complete source value type.
func CellIDBroadcastCodec() s17.CellIDBroadcastValueCodec {
	return func() s17.CellIDBroadcastValueCodec {
		sealed := s17.CellIDBroadcastValueCodec{}
		*s17.BridgeCellIDBroadcastValueCodecFieldPath(&sealed) = "CellIDBroadcast"
		*s17.BridgeCellIDBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellIDBroadcast, error) {
			var complete CellIDBroadcastComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CellIDBroadcast
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCellIDBroadcastValueCodecFieldEncode(&sealed) = func(value s17.CellIDBroadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIDBroadcastComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCellIDBroadcastValueCodecFieldCapture(&sealed) = func(v s17.CellIDBroadcast, options aper.DecodeState) (s17.CellIDBroadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCellIDBroadcast(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellIDBroadcastValueCodecFieldCompare(&sealed) = func(v s17.CellIDBroadcast, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCellIDBroadcast(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeCellIDBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDBroadcast"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIDCancelledCodec binds the complete source value type.
func CellIDCancelledCodec() s17.CellIDCancelledValueCodec {
	return func() s17.CellIDCancelledValueCodec {
		sealed := s17.CellIDCancelledValueCodec{}
		*s17.BridgeCellIDCancelledValueCodecFieldPath(&sealed) = "CellIDCancelled"
		*s17.BridgeCellIDCancelledValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellIDCancelled, error) {
			var complete CellIDCancelledComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CellIDCancelled
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCellIDCancelledValueCodecFieldEncode(&sealed) = func(value s17.CellIDCancelled, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIDCancelledComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCellIDCancelledValueCodecFieldCapture(&sealed) = func(v s17.CellIDCancelled, options aper.DecodeState) (s17.CellIDCancelled, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCellIDCancelled(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellIDCancelledValueCodecFieldCompare(&sealed) = func(v s17.CellIDCancelled, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCellIDCancelled(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeCellIDCancelledValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIDCancelled"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIdListforMDTCodec binds the complete source value type.
func CellIdListforMDTCodec() s17.CellIdListforMDTValueCodec {
	return func() s17.CellIdListforMDTValueCodec {
		sealed := s17.CellIdListforMDTValueCodec{}
		*s17.BridgeCellIdListforMDTValueCodecFieldPath(&sealed) = "CellIdListforMDT"
		*s17.BridgeCellIdListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CellIdListforMDT, error) {
			var complete CellIdListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s17.CellIdListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s17.BridgeCellIdListforMDTValueCodecFieldEncode(&sealed) = func(value s17.CellIdListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := CellIdListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s17.BridgeCellIdListforMDTValueCodecFieldCapture(&sealed) = func(v s17.CellIdListforMDT, options aper.DecodeState) (s17.CellIdListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s21.BridgeCaptureS1APCellIdListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCellIdListforMDTValueCodecFieldCompare(&sealed) = func(v s17.CellIdListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCellIdListforMDT(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s17.BridgeCellIdListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBEarlyStatusTransferTransparentContainerCodec binds the complete APER value type.
func ENBEarlyStatusTransferTransparentContainerCodec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Codec()
}

// STMSICodec binds the complete APER value type.
func STMSICodec() s28.STMSIValueCodec { return ENBCPRelocationIndicationIEs().STMSI().Codec() }

// TAICodec binds the complete APER value type.
func TAICodec() s32.TAIValueCodec { return ENBCPRelocationIndicationIEs().TAI().Codec() }

// ULCPSecurityInformationCodec binds the complete APER value type.
func ULCPSecurityInformationCodec() ULCPSecurityInformationValueCodec {
	return ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Codec()
}
func BridgeActivatedCellsListCompleteFieldPerPadding(v *ActivatedCellsListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeActivatedCellsListCompleteFieldReceived(v *ActivatedCellsListComplete) *bool {
	return &v.received
}
func BridgeActivatedCellsListCompleteFieldReceivedAbsolute(v *ActivatedCellsListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeActivatedCellsListCompleteFieldReceivedBytes(v *ActivatedCellsListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeActivatedCellsListCompleteFieldReceivedLocation(v *ActivatedCellsListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeActivatedCellsListCompleteFieldReplay(v *ActivatedCellsListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeActivatedCellsListCompleteFieldStream(v *ActivatedCellsListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeActivatedCellsListCompleteFieldWithoutReplay(v *ActivatedCellsListComplete) *bool {
	return &v.withoutReplay
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERBudget(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERBudgetValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERChanged(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERChangedValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERLegacy(v *ActivatedCellsListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERNewValue(v *ActivatedCellsListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeActivatedCellsListCompleteMethodMarshalAPERPlanned(v *ActivatedCellsListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeActivatedCellsListCompleteMethodUnmarshalAPERLegacy(v *ActivatedCellsListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeActivatedCellsListCompleteMethodUnmarshalAPERWithOptions(v *ActivatedCellsListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBPLMNsCompleteFieldPerPadding(v *BPLMNsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBPLMNsCompleteFieldReceived(v *BPLMNsComplete) *bool         { return &v.received }
func BridgeBPLMNsCompleteFieldReceivedAbsolute(v *BPLMNsComplete) *bool { return &v.receivedAbsolute }
func BridgeBPLMNsCompleteFieldReceivedBytes(v *BPLMNsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBPLMNsCompleteFieldReceivedLocation(v *BPLMNsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBPLMNsCompleteFieldReplay(v *BPLMNsComplete) *aper.Snapshot { return &v.replay }
func BridgeBPLMNsCompleteFieldStream(v *BPLMNsComplete) *aper.WireSpan { return &v.stream }
func BridgeBPLMNsCompleteFieldWithoutReplay(v *BPLMNsComplete) *bool   { return &v.withoutReplay }
func BridgeBPLMNsCompleteMethodMarshalAPERBudget(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERBudgetValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERChanged(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodMarshalAPERChangedValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodMarshalAPERLegacy(v *BPLMNsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBPLMNsCompleteMethodMarshalAPERNewValue(v *BPLMNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBPLMNsCompleteMethodMarshalAPERPlanned(v *BPLMNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBPLMNsCompleteMethodUnmarshalAPERLegacy(v *BPLMNsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBPLMNsCompleteMethodUnmarshalAPERWithOptions(v *BPLMNsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldPerPadding(v *BearersSubjectToDLDiscardingListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceived(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedAbsolute(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedBytes(v *BearersSubjectToDLDiscardingListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReceivedLocation(v *BearersSubjectToDLDiscardingListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldReplay(v *BearersSubjectToDLDiscardingListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldStream(v *BearersSubjectToDLDiscardingListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToDLDiscardingListCompleteFieldWithoutReplay(v *BearersSubjectToDLDiscardingListComplete) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERBudget(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERBudgetValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERChanged(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERChangedValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERNewValue(v *BearersSubjectToDLDiscardingListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERPlanned(v *BearersSubjectToDLDiscardingListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERWithOptions(v *BearersSubjectToDLDiscardingListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldPerPadding(v *BearersSubjectToEarlyStatusTransferListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldReceived(v *BearersSubjectToEarlyStatusTransferListComplete) *bool {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldReceivedAbsolute(v *BearersSubjectToEarlyStatusTransferListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldReceivedBytes(v *BearersSubjectToEarlyStatusTransferListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldReceivedLocation(v *BearersSubjectToEarlyStatusTransferListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldReplay(v *BearersSubjectToEarlyStatusTransferListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldStream(v *BearersSubjectToEarlyStatusTransferListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteFieldWithoutReplay(v *BearersSubjectToEarlyStatusTransferListComplete) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERBudget(v *BearersSubjectToEarlyStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERBudgetValue(v *BearersSubjectToEarlyStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERChanged(v *BearersSubjectToEarlyStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERChangedValue(v *BearersSubjectToEarlyStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERLegacy(v *BearersSubjectToEarlyStatusTransferListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERNewValue(v *BearersSubjectToEarlyStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodMarshalAPERPlanned(v *BearersSubjectToEarlyStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodUnmarshalAPERLegacy(v *BearersSubjectToEarlyStatusTransferListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferListCompleteMethodUnmarshalAPERWithOptions(v *BearersSubjectToEarlyStatusTransferListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldPerPadding(v *BearersSubjectToStatusTransferListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldReceived(v *BearersSubjectToStatusTransferListComplete) *bool {
	return &v.received
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldReceivedAbsolute(v *BearersSubjectToStatusTransferListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldReceivedBytes(v *BearersSubjectToStatusTransferListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldReceivedLocation(v *BearersSubjectToStatusTransferListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldReplay(v *BearersSubjectToStatusTransferListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldStream(v *BearersSubjectToStatusTransferListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeBearersSubjectToStatusTransferListCompleteFieldWithoutReplay(v *BearersSubjectToStatusTransferListComplete) *bool {
	return &v.withoutReplay
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERBudget(v *BearersSubjectToStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERBudgetValue(v *BearersSubjectToStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERChanged(v *BearersSubjectToStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERChangedValue(v *BearersSubjectToStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERLegacy(v *BearersSubjectToStatusTransferListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERNewValue(v *BearersSubjectToStatusTransferListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodMarshalAPERPlanned(v *BearersSubjectToStatusTransferListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodUnmarshalAPERLegacy(v *BearersSubjectToStatusTransferListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBearersSubjectToStatusTransferListCompleteMethodUnmarshalAPERWithOptions(v *BearersSubjectToStatusTransferListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeBluetoothMeasConfigNameListCompleteFieldPerPadding(v *BluetoothMeasConfigNameListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeBluetoothMeasConfigNameListCompleteFieldReceived(v *BluetoothMeasConfigNameListComplete) *bool {
	return &v.received
}
func BridgeBluetoothMeasConfigNameListCompleteFieldReceivedAbsolute(v *BluetoothMeasConfigNameListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeBluetoothMeasConfigNameListCompleteFieldReceivedBytes(v *BluetoothMeasConfigNameListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeBluetoothMeasConfigNameListCompleteFieldReceivedLocation(v *BluetoothMeasConfigNameListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeBluetoothMeasConfigNameListCompleteFieldReplay(v *BluetoothMeasConfigNameListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeBluetoothMeasConfigNameListCompleteFieldStream(v *BluetoothMeasConfigNameListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeBluetoothMeasConfigNameListCompleteFieldWithoutReplay(v *BluetoothMeasConfigNameListComplete) *bool {
	return &v.withoutReplay
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERBudget(v *BluetoothMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERBudgetValue(v *BluetoothMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERChanged(v *BluetoothMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERChangedValue(v *BluetoothMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERLegacy(v *BluetoothMeasConfigNameListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERNewValue(v *BluetoothMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodMarshalAPERPlanned(v *BluetoothMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodUnmarshalAPERLegacy(v *BluetoothMeasConfigNameListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeBluetoothMeasConfigNameListCompleteMethodUnmarshalAPERWithOptions(v *BluetoothMeasConfigNameListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCNTypeRestrictionsCompleteFieldPerPadding(v *CNTypeRestrictionsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCNTypeRestrictionsCompleteFieldReceived(v *CNTypeRestrictionsComplete) *bool {
	return &v.received
}
func BridgeCNTypeRestrictionsCompleteFieldReceivedAbsolute(v *CNTypeRestrictionsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCNTypeRestrictionsCompleteFieldReceivedBytes(v *CNTypeRestrictionsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCNTypeRestrictionsCompleteFieldReceivedLocation(v *CNTypeRestrictionsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCNTypeRestrictionsCompleteFieldReplay(v *CNTypeRestrictionsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsCompleteFieldStream(v *CNTypeRestrictionsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCNTypeRestrictionsCompleteFieldWithoutReplay(v *CNTypeRestrictionsComplete) *bool {
	return &v.withoutReplay
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERBudget(v *CNTypeRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERBudgetValue(v *CNTypeRestrictionsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERChanged(v *CNTypeRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERChangedValue(v *CNTypeRestrictionsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERLegacy(v *CNTypeRestrictionsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERNewValue(v *CNTypeRestrictionsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCNTypeRestrictionsCompleteMethodMarshalAPERPlanned(v *CNTypeRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCNTypeRestrictionsCompleteMethodUnmarshalAPERLegacy(v *CNTypeRestrictionsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCNTypeRestrictionsCompleteMethodUnmarshalAPERWithOptions(v *CNTypeRestrictionsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCSGIdListCompleteFieldPerPadding(v *CSGIdListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCSGIdListCompleteFieldReceived(v *CSGIdListComplete) *bool { return &v.received }
func BridgeCSGIdListCompleteFieldReceivedAbsolute(v *CSGIdListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCSGIdListCompleteFieldReceivedBytes(v *CSGIdListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCSGIdListCompleteFieldReceivedLocation(v *CSGIdListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCSGIdListCompleteFieldReplay(v *CSGIdListComplete) *aper.Snapshot { return &v.replay }
func BridgeCSGIdListCompleteFieldStream(v *CSGIdListComplete) *aper.WireSpan { return &v.stream }
func BridgeCSGIdListCompleteFieldWithoutReplay(v *CSGIdListComplete) *bool   { return &v.withoutReplay }
func BridgeCSGIdListCompleteMethodMarshalAPERBudget(v *CSGIdListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCSGIdListCompleteMethodMarshalAPERBudgetValue(v *CSGIdListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCSGIdListCompleteMethodMarshalAPERChanged(v *CSGIdListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCSGIdListCompleteMethodMarshalAPERChangedValue(v *CSGIdListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCSGIdListCompleteMethodMarshalAPERLegacy(v *CSGIdListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCSGIdListCompleteMethodMarshalAPERNewValue(v *CSGIdListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCSGIdListCompleteMethodMarshalAPERPlanned(v *CSGIdListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCSGIdListCompleteMethodUnmarshalAPERLegacy(v *CSGIdListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCSGIdListCompleteMethodUnmarshalAPERWithOptions(v *CSGIdListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCancelledCellinEAICompleteFieldPerPadding(v *CancelledCellinEAIComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCancelledCellinEAICompleteFieldReceived(v *CancelledCellinEAIComplete) *bool {
	return &v.received
}
func BridgeCancelledCellinEAICompleteFieldReceivedAbsolute(v *CancelledCellinEAIComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCancelledCellinEAICompleteFieldReceivedBytes(v *CancelledCellinEAIComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCancelledCellinEAICompleteFieldReceivedLocation(v *CancelledCellinEAIComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCancelledCellinEAICompleteFieldReplay(v *CancelledCellinEAIComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCancelledCellinEAICompleteFieldStream(v *CancelledCellinEAIComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCancelledCellinEAICompleteFieldWithoutReplay(v *CancelledCellinEAIComplete) *bool {
	return &v.withoutReplay
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERBudget(v *CancelledCellinEAIComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERBudgetValue(v *CancelledCellinEAIComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERChanged(v *CancelledCellinEAIComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERChangedValue(v *CancelledCellinEAIComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERLegacy(v *CancelledCellinEAIComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERNewValue(v *CancelledCellinEAIComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCancelledCellinEAICompleteMethodMarshalAPERPlanned(v *CancelledCellinEAIComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCancelledCellinEAICompleteMethodUnmarshalAPERLegacy(v *CancelledCellinEAIComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCancelledCellinEAICompleteMethodUnmarshalAPERWithOptions(v *CancelledCellinEAIComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCancelledCellinTAICompleteFieldPerPadding(v *CancelledCellinTAIComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCancelledCellinTAICompleteFieldReceived(v *CancelledCellinTAIComplete) *bool {
	return &v.received
}
func BridgeCancelledCellinTAICompleteFieldReceivedAbsolute(v *CancelledCellinTAIComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCancelledCellinTAICompleteFieldReceivedBytes(v *CancelledCellinTAIComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCancelledCellinTAICompleteFieldReceivedLocation(v *CancelledCellinTAIComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCancelledCellinTAICompleteFieldReplay(v *CancelledCellinTAIComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCancelledCellinTAICompleteFieldStream(v *CancelledCellinTAIComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCancelledCellinTAICompleteFieldWithoutReplay(v *CancelledCellinTAIComplete) *bool {
	return &v.withoutReplay
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERBudget(v *CancelledCellinTAIComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERBudgetValue(v *CancelledCellinTAIComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERChanged(v *CancelledCellinTAIComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERChangedValue(v *CancelledCellinTAIComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERLegacy(v *CancelledCellinTAIComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERNewValue(v *CancelledCellinTAIComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCancelledCellinTAICompleteMethodMarshalAPERPlanned(v *CancelledCellinTAIComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCancelledCellinTAICompleteMethodUnmarshalAPERLegacy(v *CancelledCellinTAIComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCancelledCellinTAICompleteMethodUnmarshalAPERWithOptions(v *CancelledCellinTAIComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCandidateCellListCompleteFieldPerPadding(v *CandidateCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCandidateCellListCompleteFieldReceived(v *CandidateCellListComplete) *bool {
	return &v.received
}
func BridgeCandidateCellListCompleteFieldReceivedAbsolute(v *CandidateCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCandidateCellListCompleteFieldReceivedBytes(v *CandidateCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCandidateCellListCompleteFieldReceivedLocation(v *CandidateCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCandidateCellListCompleteFieldReplay(v *CandidateCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCandidateCellListCompleteFieldStream(v *CandidateCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCandidateCellListCompleteFieldWithoutReplay(v *CandidateCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeCandidateCellListCompleteMethodMarshalAPERBudget(v *CandidateCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCandidateCellListCompleteMethodMarshalAPERBudgetValue(v *CandidateCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCandidateCellListCompleteMethodMarshalAPERChanged(v *CandidateCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCandidateCellListCompleteMethodMarshalAPERChangedValue(v *CandidateCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCandidateCellListCompleteMethodMarshalAPERLegacy(v *CandidateCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCandidateCellListCompleteMethodMarshalAPERNewValue(v *CandidateCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCandidateCellListCompleteMethodMarshalAPERPlanned(v *CandidateCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCandidateCellListCompleteMethodUnmarshalAPERLegacy(v *CandidateCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCandidateCellListCompleteMethodUnmarshalAPERWithOptions(v *CandidateCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCandidatePCIListCompleteFieldPerPadding(v *CandidatePCIListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCandidatePCIListCompleteFieldReceived(v *CandidatePCIListComplete) *bool {
	return &v.received
}
func BridgeCandidatePCIListCompleteFieldReceivedAbsolute(v *CandidatePCIListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCandidatePCIListCompleteFieldReceivedBytes(v *CandidatePCIListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCandidatePCIListCompleteFieldReceivedLocation(v *CandidatePCIListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCandidatePCIListCompleteFieldReplay(v *CandidatePCIListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCandidatePCIListCompleteFieldStream(v *CandidatePCIListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCandidatePCIListCompleteFieldWithoutReplay(v *CandidatePCIListComplete) *bool {
	return &v.withoutReplay
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERBudget(v *CandidatePCIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERBudgetValue(v *CandidatePCIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERChanged(v *CandidatePCIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERChangedValue(v *CandidatePCIListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERLegacy(v *CandidatePCIListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERNewValue(v *CandidatePCIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCandidatePCIListCompleteMethodMarshalAPERPlanned(v *CandidatePCIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCandidatePCIListCompleteMethodUnmarshalAPERLegacy(v *CandidatePCIListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCandidatePCIListCompleteMethodUnmarshalAPERWithOptions(v *CandidatePCIListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellIDBroadcastCompleteFieldPerPadding(v *CellIDBroadcastComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCellIDBroadcastCompleteFieldReceived(v *CellIDBroadcastComplete) *bool { return &v.received }
func BridgeCellIDBroadcastCompleteFieldReceivedAbsolute(v *CellIDBroadcastComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCellIDBroadcastCompleteFieldReceivedBytes(v *CellIDBroadcastComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellIDBroadcastCompleteFieldReceivedLocation(v *CellIDBroadcastComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellIDBroadcastCompleteFieldReplay(v *CellIDBroadcastComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIDBroadcastCompleteFieldStream(v *CellIDBroadcastComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCellIDBroadcastCompleteFieldWithoutReplay(v *CellIDBroadcastComplete) *bool {
	return &v.withoutReplay
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERBudget(v *CellIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERBudgetValue(v *CellIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERChanged(v *CellIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERChangedValue(v *CellIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERLegacy(v *CellIDBroadcastComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERNewValue(v *CellIDBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellIDBroadcastCompleteMethodMarshalAPERPlanned(v *CellIDBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellIDBroadcastCompleteMethodUnmarshalAPERLegacy(v *CellIDBroadcastComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellIDBroadcastCompleteMethodUnmarshalAPERWithOptions(v *CellIDBroadcastComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellIDCancelledCompleteFieldPerPadding(v *CellIDCancelledComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCellIDCancelledCompleteFieldReceived(v *CellIDCancelledComplete) *bool { return &v.received }
func BridgeCellIDCancelledCompleteFieldReceivedAbsolute(v *CellIDCancelledComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCellIDCancelledCompleteFieldReceivedBytes(v *CellIDCancelledComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellIDCancelledCompleteFieldReceivedLocation(v *CellIDCancelledComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellIDCancelledCompleteFieldReplay(v *CellIDCancelledComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIDCancelledCompleteFieldStream(v *CellIDCancelledComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCellIDCancelledCompleteFieldWithoutReplay(v *CellIDCancelledComplete) *bool {
	return &v.withoutReplay
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERBudget(v *CellIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERBudgetValue(v *CellIDCancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERChanged(v *CellIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERChangedValue(v *CellIDCancelledComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERLegacy(v *CellIDCancelledComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERNewValue(v *CellIDCancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellIDCancelledCompleteMethodMarshalAPERPlanned(v *CellIDCancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellIDCancelledCompleteMethodUnmarshalAPERLegacy(v *CellIDCancelledComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellIDCancelledCompleteMethodUnmarshalAPERWithOptions(v *CellIDCancelledComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellIdListforMDTCompleteFieldPerPadding(v *CellIdListforMDTComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCellIdListforMDTCompleteFieldReceived(v *CellIdListforMDTComplete) *bool {
	return &v.received
}
func BridgeCellIdListforMDTCompleteFieldReceivedAbsolute(v *CellIdListforMDTComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCellIdListforMDTCompleteFieldReceivedBytes(v *CellIdListforMDTComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellIdListforMDTCompleteFieldReceivedLocation(v *CellIdListforMDTComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellIdListforMDTCompleteFieldReplay(v *CellIdListforMDTComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIdListforMDTCompleteFieldStream(v *CellIdListforMDTComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCellIdListforMDTCompleteFieldWithoutReplay(v *CellIdListforMDTComplete) *bool {
	return &v.withoutReplay
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERBudget(v *CellIdListforMDTComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERBudgetValue(v *CellIdListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERChanged(v *CellIdListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERChangedValue(v *CellIdListforMDTComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERLegacy(v *CellIdListforMDTComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERNewValue(v *CellIdListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellIdListforMDTCompleteMethodMarshalAPERPlanned(v *CellIdListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellIdListforMDTCompleteMethodUnmarshalAPERLegacy(v *CellIdListforMDTComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellIdListforMDTCompleteMethodUnmarshalAPERWithOptions(v *CellIdListforMDTComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeCellIdListforQMCCompleteFieldPerPadding(v *CellIdListforQMCComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeCellIdListforQMCCompleteFieldReceived(v *CellIdListforQMCComplete) *bool {
	return &v.received
}
func BridgeCellIdListforQMCCompleteFieldReceivedAbsolute(v *CellIdListforQMCComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeCellIdListforQMCCompleteFieldReceivedBytes(v *CellIdListforQMCComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeCellIdListforQMCCompleteFieldReceivedLocation(v *CellIdListforQMCComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeCellIdListforQMCCompleteFieldReplay(v *CellIdListforQMCComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeCellIdListforQMCCompleteFieldStream(v *CellIdListforQMCComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeCellIdListforQMCCompleteFieldWithoutReplay(v *CellIdListforQMCComplete) *bool {
	return &v.withoutReplay
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERBudget(v *CellIdListforQMCComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERBudgetValue(v *CellIdListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERChanged(v *CellIdListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERChangedValue(v *CellIdListforQMCComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERLegacy(v *CellIdListforQMCComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERNewValue(v *CellIdListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeCellIdListforQMCCompleteMethodMarshalAPERPlanned(v *CellIdListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeCellIdListforQMCCompleteMethodUnmarshalAPERLegacy(v *CellIdListforQMCComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCellIdListforQMCCompleteMethodUnmarshalAPERWithOptions(v *CellIdListforQMCComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBCPRelocationIndicationAPERValueFieldContext(v *ENBCPRelocationIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationAPERValueFieldReceived(v *ENBCPRelocationIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationAPERValueFieldReplay(v *ENBCPRelocationIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldCodec(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldGet(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldInfo(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationENBUES1APIDIEBindingFieldInject(v *ENBCPRelocationIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldCodec(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *s18.EUTRANCGIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldGet(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s17.EUTRANCGI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldInfo(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationEUTRANCGIIEBindingFieldInject(v *ENBCPRelocationIndicationEUTRANCGIIEBinding) *func(s17.EUTRANCGI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationFieldExtCount(v *ENBCPRelocationIndication) *int64 {
	return &v.extCount
}
func BridgeENBCPRelocationIndicationFieldExtData(v *ENBCPRelocationIndication) *[][]byte {
	return &v.extData
}
func BridgeENBCPRelocationIndicationFieldExtOrigin(v *ENBCPRelocationIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBCPRelocationIndicationFieldExtPresent(v *ENBCPRelocationIndication) *[]bool {
	return &v.extPresent
}
func BridgeENBCPRelocationIndicationFieldExtWire(v *ENBCPRelocationIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBCPRelocationIndicationFieldPerExtPadding(v *ENBCPRelocationIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBCPRelocationIndicationFieldPerPadding(v *ENBCPRelocationIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBCPRelocationIndicationFieldProtocolIEsIndef(v *ENBCPRelocationIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBCPRelocationIndicationFieldReceived(v *ENBCPRelocationIndication) *bool {
	return &v.received
}
func BridgeENBCPRelocationIndicationFieldReceivedAbsolute(v *ENBCPRelocationIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeENBCPRelocationIndicationFieldReceivedBytes(v *ENBCPRelocationIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBCPRelocationIndicationFieldReceivedLocation(v *ENBCPRelocationIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBCPRelocationIndicationFieldReplay(v *ENBCPRelocationIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationFieldStream(v *ENBCPRelocationIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeENBCPRelocationIndicationFieldWithoutReplay(v *ENBCPRelocationIndication) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldContext(v *ENBCPRelocationIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldReceived(v *ENBCPRelocationIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldReplay(v *ENBCPRelocationIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEContainerAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldCapture(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldCompare(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldContext(v *ENBCPRelocationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldDecode(v *ENBCPRelocationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldEncode(v *ENBCPRelocationIndicationIEContainerValueCodec) *func(ENBCPRelocationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecFieldPath(v *ENBCPRelocationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEContainerValueCodec, a0 ENBCPRelocationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEContainerValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEContainerValueCodec, a0 ENBCPRelocationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldContext(v *ENBCPRelocationIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldReceived(v *ENBCPRelocationIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldReplay(v *ENBCPRelocationIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEFieldAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEFieldFieldReceived(v *ENBCPRelocationIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEFieldFieldReplay(v *ENBCPRelocationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEFieldFieldStream(v *ENBCPRelocationIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBCPRelocationIndicationIEFieldFieldWithoutReplay(v *ENBCPRelocationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEFieldMethodMarshalAPERTo(v *ENBCPRelocationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBCPRelocationIndicationIEFieldMethodUnmarshalAPERFrom(v *ENBCPRelocationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldCapture(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, aper.DecodeState) (ENBCPRelocationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldCompare(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldContext(v *ENBCPRelocationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldDecode(v *ENBCPRelocationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEField, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldEncode(v *ENBCPRelocationIndicationIEFieldValueCodec) *func(ENBCPRelocationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecFieldPath(v *ENBCPRelocationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEFieldValueCodec, a0 ENBCPRelocationIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEFieldValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEFieldValueCodec, a0 ENBCPRelocationIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIETableMethodInfoENBUES1APID(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoEUTRANCGI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoEUTRANCGI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoLTENTNTAIInformation(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoLTENTNTAIInformation()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoSTMSI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoSTMSI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoTAI(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoTAI()
}
func BridgeENBCPRelocationIndicationIETableMethodInfoULCPSecurityInformation(v ENBCPRelocationIndicationIETable) s00.FieldInfo {
	return v.infoULCPSecurityInformation()
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEValueFieldId(v *ENBCPRelocationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBCPRelocationIndicationIEValueFieldIsOpaque(v *ENBCPRelocationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBCPRelocationIndicationIEValueFieldOpaque(v *ENBCPRelocationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBCPRelocationIndicationIEValueFieldReceived(v *ENBCPRelocationIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueFieldReplay(v *ENBCPRelocationIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueFieldRowENBUES1APID(v *ENBCPRelocationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBCPRelocationIndicationIEValueFieldRowEUTRANCGI(v *ENBCPRelocationIndicationIEValue) **s17.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowLTENTNTAIInformation(v *ENBCPRelocationIndicationIEValue) **s18.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeENBCPRelocationIndicationIEValueFieldRowSTMSI(v *ENBCPRelocationIndicationIEValue) **s28.STMSI {
	return &v.rowSTMSI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowTAI(v *ENBCPRelocationIndicationIEValue) **s32.TAI {
	return &v.rowTAI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowULCPSecurityInformation(v *ENBCPRelocationIndicationIEValue) **ULCPSecurityInformation {
	return &v.rowULCPSecurityInformation
}
func BridgeENBCPRelocationIndicationIEValueMethodCaptureSemantics(v ENBCPRelocationIndicationIEValue, a0 aper.SemanticCapture) ENBCPRelocationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodCompareSemantics(v ENBCPRelocationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodDecode(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBCPRelocationIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBCPRelocationIndicationIEValueMethodEncode(v ENBCPRelocationIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBCPRelocationIndicationIEValueMethodEncodeFresh(v ENBCPRelocationIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBCPRelocationIndicationIEValueMethodMatchesID(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBCPRelocationIndicationIEValueMethodReason(v ENBCPRelocationIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBCPRelocationIndicationIEValueMethodRule(v ENBCPRelocationIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *func(ENBCPRelocationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec, a0 ENBCPRelocationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldCodec(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *s18.LTENTNTAIInformationValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldGet(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s18.LTENTNTAIInformation, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldInfo(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationLTENTNTAIInformationIEBindingFieldInject(v *ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) *func(s18.LTENTNTAIInformation) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERBudgetValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERChanged(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERChangedValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERLegacy(v *ENBCPRelocationIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERNewValue(v *ENBCPRelocationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERPlanned(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERTo(v *ENBCPRelocationIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERFrom(v *ENBCPRelocationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERLegacy(v *ENBCPRelocationIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERWithOptions(v *ENBCPRelocationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldCodec(v *ENBCPRelocationIndicationSTMSIIEBinding) *s28.STMSIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldGet(v *ENBCPRelocationIndicationSTMSIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s28.STMSI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldInfo(v *ENBCPRelocationIndicationSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationSTMSIIEBindingFieldInject(v *ENBCPRelocationIndicationSTMSIIEBinding) *func(s28.STMSI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldCodec(v *ENBCPRelocationIndicationTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldGet(v *ENBCPRelocationIndicationTAIIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*s32.TAI, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldInfo(v *ENBCPRelocationIndicationTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationTAIIEBindingFieldInject(v *ENBCPRelocationIndicationTAIIEBinding) *func(s32.TAI) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldCodec(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *ULCPSecurityInformationValueCodec {
	return &v.codec
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldGet(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *func(*ENBCPRelocationIndicationIEValue) (*ULCPSecurityInformation, bool) {
	return &v.get
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldInfo(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBCPRelocationIndicationULCPSecurityInformationIEBindingFieldInject(v *ENBCPRelocationIndicationULCPSecurityInformationIEBinding) *func(ULCPSecurityInformation) ENBCPRelocationIndicationIEValue {
	return &v.inject
}
func BridgeENBCPRelocationIndicationValueCodecFieldCapture(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, aper.DecodeState) (ENBCPRelocationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeENBCPRelocationIndicationValueCodecFieldCompare(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBCPRelocationIndicationValueCodecFieldContext(v *ENBCPRelocationIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBCPRelocationIndicationValueCodecFieldDecode(v *ENBCPRelocationIndicationValueCodec) *func([]byte, aper.DecodeState) (ENBCPRelocationIndication, error) {
	return &v.decode
}
func BridgeENBCPRelocationIndicationValueCodecFieldEncode(v *ENBCPRelocationIndicationValueCodec) *func(ENBCPRelocationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBCPRelocationIndicationValueCodecFieldPath(v *ENBCPRelocationIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBCPRelocationIndicationValueCodecMethodEncodeBudgetValue(v ENBCPRelocationIndicationValueCodec, a0 ENBCPRelocationIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBCPRelocationIndicationValueCodecMethodEncodeChanged(v ENBCPRelocationIndicationValueCodec, a0 ENBCPRelocationIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferAPERValueFieldContext(v *ENBEarlyStatusTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferAPERValueFieldReceived(v *ENBEarlyStatusTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferAPERValueFieldReplay(v *ENBEarlyStatusTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldCodec(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *ENBEarlyStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldGet(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInfo(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInject(v *ENBEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(ENBEarlyStatusTransferTransparentContainer) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldCodec(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldGet(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldInfo(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferENBUES1APIDIEBindingFieldInject(v *ENBEarlyStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferFieldExtCount(v *ENBEarlyStatusTransfer) *int64   { return &v.extCount }
func BridgeENBEarlyStatusTransferFieldExtData(v *ENBEarlyStatusTransfer) *[][]byte { return &v.extData }
func BridgeENBEarlyStatusTransferFieldExtOrigin(v *ENBEarlyStatusTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBEarlyStatusTransferFieldExtPresent(v *ENBEarlyStatusTransfer) *[]bool {
	return &v.extPresent
}
func BridgeENBEarlyStatusTransferFieldExtWire(v *ENBEarlyStatusTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBEarlyStatusTransferFieldPerExtPadding(v *ENBEarlyStatusTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBEarlyStatusTransferFieldPerPadding(v *ENBEarlyStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBEarlyStatusTransferFieldProtocolIEsIndef(v *ENBEarlyStatusTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeENBEarlyStatusTransferFieldReceived(v *ENBEarlyStatusTransfer) *bool { return &v.received }
func BridgeENBEarlyStatusTransferFieldReceivedAbsolute(v *ENBEarlyStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBEarlyStatusTransferFieldReceivedBytes(v *ENBEarlyStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBEarlyStatusTransferFieldReceivedLocation(v *ENBEarlyStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBEarlyStatusTransferFieldReplay(v *ENBEarlyStatusTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferFieldStream(v *ENBEarlyStatusTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferFieldWithoutReplay(v *ENBEarlyStatusTransfer) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldContext(v *ENBEarlyStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldContext(v *ENBEarlyStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferIEContainerValueCodec) *func(ENBEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecFieldPath(v *ENBEarlyStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEContainerValueCodec, a0 ENBEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEContainerValueCodec, a0 ENBEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldContext(v *ENBEarlyStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldReceived(v *ENBEarlyStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldReplay(v *ENBEarlyStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEFieldAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEFieldFieldReceived(v *ENBEarlyStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEFieldFieldReplay(v *ENBEarlyStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEFieldFieldStream(v *ENBEarlyStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferIEFieldFieldWithoutReplay(v *ENBEarlyStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldCapture(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, aper.DecodeState) (ENBEarlyStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldCompare(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldContext(v *ENBEarlyStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldDecode(v *ENBEarlyStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEField, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldEncode(v *ENBEarlyStatusTransferIEFieldValueCodec) *func(ENBEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecFieldPath(v *ENBEarlyStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEFieldValueCodec, a0 ENBEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEFieldValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEFieldValueCodec, a0 ENBEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIETableMethodInfoENBEarlyStatusTransferTransparentContainer(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBEarlyStatusTransferTransparentContainer()
}
func BridgeENBEarlyStatusTransferIETableMethodInfoENBUES1APID(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeENBEarlyStatusTransferIETableMethodInfoMMEUES1APID(v ENBEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEValueFieldId(v *ENBEarlyStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBEarlyStatusTransferIEValueFieldIsOpaque(v *ENBEarlyStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBEarlyStatusTransferIEValueFieldOpaque(v *ENBEarlyStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBEarlyStatusTransferIEValueFieldReceived(v *ENBEarlyStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueFieldReplay(v *ENBEarlyStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferIEValue) **ENBEarlyStatusTransferTransparentContainer {
	return &v.rowENBEarlyStatusTransferTransparentContainer
}
func BridgeENBEarlyStatusTransferIEValueFieldRowENBUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBEarlyStatusTransferIEValueFieldRowMMEUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeENBEarlyStatusTransferIEValueMethodCaptureSemantics(v ENBEarlyStatusTransferIEValue, a0 aper.SemanticCapture) ENBEarlyStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodCompareSemantics(v ENBEarlyStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodDecode(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBEarlyStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBEarlyStatusTransferIEValueMethodEncode(v ENBEarlyStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBEarlyStatusTransferIEValueMethodEncodeFresh(v ENBEarlyStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBEarlyStatusTransferIEValueMethodMatchesID(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBEarlyStatusTransferIEValueMethodReason(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBEarlyStatusTransferIEValueMethodRule(v ENBEarlyStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(ENBEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 ENBEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldCodec(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldGet(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *func(*ENBEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldInfo(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferMMEUES1APIDIEBindingFieldInject(v *ENBEarlyStatusTransferMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ENBEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v *ENBEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERBudgetValue(v *ENBEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERChanged(v *ENBEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERChangedValue(v *ENBEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERLegacy(v *ENBEarlyStatusTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERNewValue(v *ENBEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERPlanned(v *ENBEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERTo(v *ENBEarlyStatusTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferMethodUnmarshalAPERLegacy(v *ENBEarlyStatusTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBEarlyStatusTransferMethodUnmarshalAPERWithOptions(v *ENBEarlyStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIETableMethodInfoBearersSubjectToDLDiscardingList(v ENBEarlyStatusTransferTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoBearersSubjectToDLDiscardingList()
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldCodec(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *s15.BearersSubjectToDLDiscardingListValueCodec {
	return &v.codec
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldGet(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *func(*ENBEarlyStatusTransferTransparentContainerExtIEsValue) (*s15.BearersSubjectToDLDiscardingList, bool) {
	return &v.get
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldInfo(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBindingFieldInject(v *ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) *func(s15.BearersSubjectToDLDiscardingList) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValueFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldStream(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *func(ENBEarlyStatusTransferTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec, a0 ENBEarlyStatusTransferTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldStream(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsIEFieldMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainerExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldId(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldIsOpaque(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldOpaque(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldReceived(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldReplay(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldRowBearersSubjectToDLDiscardingList(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) **s15.BearersSubjectToDLDiscardingList {
	return &v.rowBearersSubjectToDLDiscardingList
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodCaptureSemantics(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 aper.SemanticCapture) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodCompareSemantics(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodDecode(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBEarlyStatusTransferTransparentContainerExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodEncode(v ENBEarlyStatusTransferTransparentContainerExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodEncodeFresh(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodMatchesID(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodReason(v ENBEarlyStatusTransferTransparentContainerExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueMethodRule(v ENBEarlyStatusTransferTransparentContainerExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldBearersSubjectToEarlyStatusTransferListIndef(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.bearersSubjectToEarlyStatusTransferListIndef
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtCount(v *ENBEarlyStatusTransferTransparentContainer) *int64 {
	return &v.extCount
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtData(v *ENBEarlyStatusTransferTransparentContainer) *[][]byte {
	return &v.extData
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtOrigin(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtPresent(v *ENBEarlyStatusTransferTransparentContainer) *[]bool {
	return &v.extPresent
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldExtWire(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldIEExtensionsIndef(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldPerExtPadding(v *ENBEarlyStatusTransferTransparentContainer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldPerPadding(v *ENBEarlyStatusTransferTransparentContainer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceived(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.received
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedAbsolute(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.receivedAbsolute
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedBytes(v *ENBEarlyStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReceivedLocation(v *ENBEarlyStatusTransferTransparentContainer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldReplay(v *ENBEarlyStatusTransferTransparentContainer) *aper.Snapshot {
	return &v.replay
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldStream(v *ENBEarlyStatusTransferTransparentContainer) *aper.WireSpan {
	return &v.stream
}
func BridgeENBEarlyStatusTransferTransparentContainerFieldWithoutReplay(v *ENBEarlyStatusTransferTransparentContainer) *bool {
	return &v.withoutReplay
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERBudget(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERBudgetValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERChanged(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERChangedValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERLegacy(v *ENBEarlyStatusTransferTransparentContainer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERNewValue(v *ENBEarlyStatusTransferTransparentContainer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERPlanned(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodMarshalAPERTo(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransferTransparentContainer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERLegacy(v *ENBEarlyStatusTransferTransparentContainer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBEarlyStatusTransferTransparentContainerMethodUnmarshalAPERWithOptions(v *ENBEarlyStatusTransferTransparentContainer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldCapture(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldCompare(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldContext(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldDecode(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransferTransparentContainer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldEncode(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *func(ENBEarlyStatusTransferTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecFieldPath(v *ENBEarlyStatusTransferTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferTransparentContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferTransparentContainerValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferTransparentContainerValueCodec, a0 ENBEarlyStatusTransferTransparentContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBEarlyStatusTransferValueCodecFieldCapture(v *ENBEarlyStatusTransferValueCodec) *func(ENBEarlyStatusTransfer, aper.DecodeState) (ENBEarlyStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBEarlyStatusTransferValueCodecFieldCompare(v *ENBEarlyStatusTransferValueCodec) *func(ENBEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBEarlyStatusTransferValueCodecFieldContext(v *ENBEarlyStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBEarlyStatusTransferValueCodecFieldDecode(v *ENBEarlyStatusTransferValueCodec) *func([]byte, aper.DecodeState) (ENBEarlyStatusTransfer, error) {
	return &v.decode
}
func BridgeENBEarlyStatusTransferValueCodecFieldEncode(v *ENBEarlyStatusTransferValueCodec) *func(ENBEarlyStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBEarlyStatusTransferValueCodecFieldPath(v *ENBEarlyStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBEarlyStatusTransferValueCodecMethodEncodeBudgetValue(v ENBEarlyStatusTransferValueCodec, a0 ENBEarlyStatusTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBEarlyStatusTransferValueCodecMethodEncodeChanged(v ENBEarlyStatusTransferValueCodec, a0 ENBEarlyStatusTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferAPERValueFieldContext(v *MMEEarlyStatusTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferAPERValueFieldReceived(v *MMEEarlyStatusTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferAPERValueFieldReplay(v *MMEEarlyStatusTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldCodec(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *ENBEarlyStatusTransferTransparentContainerValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldGet(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*ENBEarlyStatusTransferTransparentContainer, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInfo(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBindingFieldInject(v *MMEEarlyStatusTransferENBEarlyStatusTransferTransparentContainerIEBinding) *func(ENBEarlyStatusTransferTransparentContainer) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldCodec(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldGet(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldInfo(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferENBUES1APIDIEBindingFieldInject(v *MMEEarlyStatusTransferENBUES1APIDIEBinding) *func(s00.ENBUES1APID) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEEarlyStatusTransferFieldExtCount(v *MMEEarlyStatusTransfer) *int64   { return &v.extCount }
func BridgeMMEEarlyStatusTransferFieldExtData(v *MMEEarlyStatusTransfer) *[][]byte { return &v.extData }
func BridgeMMEEarlyStatusTransferFieldExtOrigin(v *MMEEarlyStatusTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMMEEarlyStatusTransferFieldExtPresent(v *MMEEarlyStatusTransfer) *[]bool {
	return &v.extPresent
}
func BridgeMMEEarlyStatusTransferFieldExtWire(v *MMEEarlyStatusTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMMEEarlyStatusTransferFieldPerExtPadding(v *MMEEarlyStatusTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMMEEarlyStatusTransferFieldPerPadding(v *MMEEarlyStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMMEEarlyStatusTransferFieldProtocolIEsIndef(v *MMEEarlyStatusTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeMMEEarlyStatusTransferFieldReceived(v *MMEEarlyStatusTransfer) *bool { return &v.received }
func BridgeMMEEarlyStatusTransferFieldReceivedAbsolute(v *MMEEarlyStatusTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeMMEEarlyStatusTransferFieldReceivedBytes(v *MMEEarlyStatusTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMMEEarlyStatusTransferFieldReceivedLocation(v *MMEEarlyStatusTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeMMEEarlyStatusTransferFieldReplay(v *MMEEarlyStatusTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferFieldStream(v *MMEEarlyStatusTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEEarlyStatusTransferFieldWithoutReplay(v *MMEEarlyStatusTransfer) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldContext(v *MMEEarlyStatusTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldReceived(v *MMEEarlyStatusTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldReplay(v *MMEEarlyStatusTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEContainerAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCapture(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldCompare(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldContext(v *MMEEarlyStatusTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldDecode(v *MMEEarlyStatusTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldEncode(v *MMEEarlyStatusTransferIEContainerValueCodec) *func(MMEEarlyStatusTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecFieldPath(v *MMEEarlyStatusTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEContainerValueCodec, a0 MMEEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEContainerValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEContainerValueCodec, a0 MMEEarlyStatusTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldContext(v *MMEEarlyStatusTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldReceived(v *MMEEarlyStatusTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldReplay(v *MMEEarlyStatusTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEFieldAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEFieldFieldReceived(v *MMEEarlyStatusTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEFieldFieldReplay(v *MMEEarlyStatusTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEFieldFieldStream(v *MMEEarlyStatusTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMMEEarlyStatusTransferIEFieldFieldWithoutReplay(v *MMEEarlyStatusTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldCapture(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, aper.DecodeState) (MMEEarlyStatusTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldCompare(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldContext(v *MMEEarlyStatusTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldDecode(v *MMEEarlyStatusTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEField, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldEncode(v *MMEEarlyStatusTransferIEFieldValueCodec) *func(MMEEarlyStatusTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecFieldPath(v *MMEEarlyStatusTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEFieldValueCodec, a0 MMEEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEFieldValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEFieldValueCodec, a0 MMEEarlyStatusTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoENBEarlyStatusTransferTransparentContainer(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBEarlyStatusTransferTransparentContainer()
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoENBUES1APID(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeMMEEarlyStatusTransferIETableMethodInfoMMEUES1APID(v MMEEarlyStatusTransferIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueERABIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEValueFieldId(v *MMEEarlyStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEEarlyStatusTransferIEValueFieldIsOpaque(v *MMEEarlyStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEEarlyStatusTransferIEValueFieldOpaque(v *MMEEarlyStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEEarlyStatusTransferIEValueFieldReceived(v *MMEEarlyStatusTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueFieldReplay(v *MMEEarlyStatusTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(v *MMEEarlyStatusTransferIEValue) **ENBEarlyStatusTransferTransparentContainer {
	return &v.rowENBEarlyStatusTransferTransparentContainer
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowENBUES1APID(v *MMEEarlyStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeMMEEarlyStatusTransferIEValueFieldRowMMEUES1APID(v *MMEEarlyStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeMMEEarlyStatusTransferIEValueMethodCaptureSemantics(v MMEEarlyStatusTransferIEValue, a0 aper.SemanticCapture) MMEEarlyStatusTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodCompareSemantics(v MMEEarlyStatusTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodDecode(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEEarlyStatusTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEEarlyStatusTransferIEValueMethodEncode(v MMEEarlyStatusTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMMEEarlyStatusTransferIEValueMethodEncodeFresh(v MMEEarlyStatusTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEValueMethodReason(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMMEEarlyStatusTransferIEValueMethodRule(v MMEEarlyStatusTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *func(MMEEarlyStatusTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferIEValueProtocolIEContainerListValueCodec, a0 MMEEarlyStatusTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldCodec(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldGet(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *func(*MMEEarlyStatusTransferIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldInfo(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEEarlyStatusTransferMMEUES1APIDIEBindingFieldInject(v *MMEEarlyStatusTransferMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) MMEEarlyStatusTransferIEValue {
	return &v.inject
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v *MMEEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERBudgetValue(v *MMEEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERChanged(v *MMEEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERChangedValue(v *MMEEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERLegacy(v *MMEEarlyStatusTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERNewValue(v *MMEEarlyStatusTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERPlanned(v *MMEEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferMethodMarshalAPERTo(v *MMEEarlyStatusTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEEarlyStatusTransferMethodUnmarshalAPERFrom(v *MMEEarlyStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEEarlyStatusTransferMethodUnmarshalAPERLegacy(v *MMEEarlyStatusTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMMEEarlyStatusTransferMethodUnmarshalAPERWithOptions(v *MMEEarlyStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMMEEarlyStatusTransferValueCodecFieldCapture(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, aper.DecodeState) (MMEEarlyStatusTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEEarlyStatusTransferValueCodecFieldCompare(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEEarlyStatusTransferValueCodecFieldContext(v *MMEEarlyStatusTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEEarlyStatusTransferValueCodecFieldDecode(v *MMEEarlyStatusTransferValueCodec) *func([]byte, aper.DecodeState) (MMEEarlyStatusTransfer, error) {
	return &v.decode
}
func BridgeMMEEarlyStatusTransferValueCodecFieldEncode(v *MMEEarlyStatusTransferValueCodec) *func(MMEEarlyStatusTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEEarlyStatusTransferValueCodecFieldPath(v *MMEEarlyStatusTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEEarlyStatusTransferValueCodecMethodEncodeBudgetValue(v MMEEarlyStatusTransferValueCodec, a0 MMEEarlyStatusTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeMMEEarlyStatusTransferValueCodecMethodEncodeChanged(v MMEEarlyStatusTransferValueCodec, a0 MMEEarlyStatusTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldContext(v *UESidelinkAggregateMaximumBitrateAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldReceived(v *UESidelinkAggregateMaximumBitrateAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldReplay(v *UESidelinkAggregateMaximumBitrateAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUESidelinkAggregateMaximumBitrateAPERValueFieldWithoutReplay(v *UESidelinkAggregateMaximumBitrateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtCount(v *UESidelinkAggregateMaximumBitrate) *int64 {
	return &v.extCount
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtData(v *UESidelinkAggregateMaximumBitrate) *[][]byte {
	return &v.extData
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtOrigin(v *UESidelinkAggregateMaximumBitrate) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtPresent(v *UESidelinkAggregateMaximumBitrate) *[]bool {
	return &v.extPresent
}
func BridgeUESidelinkAggregateMaximumBitrateFieldExtWire(v *UESidelinkAggregateMaximumBitrate) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUESidelinkAggregateMaximumBitrateFieldIEExtensionsIndef(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUESidelinkAggregateMaximumBitrateFieldPerExtPadding(v *UESidelinkAggregateMaximumBitrate) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(v *UESidelinkAggregateMaximumBitrate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceived(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.received
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedAbsolute(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.receivedAbsolute
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(v *UESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(v *UESidelinkAggregateMaximumBitrate) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReplay(v *UESidelinkAggregateMaximumBitrate) *aper.Snapshot {
	return &v.replay
}
func BridgeUESidelinkAggregateMaximumBitrateFieldStream(v *UESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.stream
}
func BridgeUESidelinkAggregateMaximumBitrateFieldWithoutReplay(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.withoutReplay
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudgetValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERChanged(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERChangedValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERLegacy(v *UESidelinkAggregateMaximumBitrate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERNewValue(v *UESidelinkAggregateMaximumBitrate, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERPlanned(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERTo(v *UESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(v *UESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERLegacy(v *UESidelinkAggregateMaximumBitrate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERWithOptions(v *UESidelinkAggregateMaximumBitrate, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, aper.DecodeState) (UESidelinkAggregateMaximumBitrate, aper.Snapshot) {
	return &v.capture
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(v *UESidelinkAggregateMaximumBitrateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(v *UESidelinkAggregateMaximumBitrateValueCodec) *func([]byte, aper.DecodeState) (UESidelinkAggregateMaximumBitrate, error) {
	return &v.decode
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(v *UESidelinkAggregateMaximumBitrateValueCodec) *func(UESidelinkAggregateMaximumBitrate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(v *UESidelinkAggregateMaximumBitrateValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeBudgetValue(v UESidelinkAggregateMaximumBitrateValueCodec, a0 UESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUESidelinkAggregateMaximumBitrateValueCodecMethodEncodeChanged(v UESidelinkAggregateMaximumBitrateValueCodec, a0 UESidelinkAggregateMaximumBitrate, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULCPSecurityInformationAPERValueFieldContext(v *ULCPSecurityInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULCPSecurityInformationAPERValueFieldReceived(v *ULCPSecurityInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeULCPSecurityInformationAPERValueFieldReplay(v *ULCPSecurityInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeULCPSecurityInformationAPERValueFieldWithoutReplay(v *ULCPSecurityInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeULCPSecurityInformationFieldExtCount(v *ULCPSecurityInformation) *int64 {
	return &v.extCount
}
func BridgeULCPSecurityInformationFieldExtData(v *ULCPSecurityInformation) *[][]byte {
	return &v.extData
}
func BridgeULCPSecurityInformationFieldExtOrigin(v *ULCPSecurityInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeULCPSecurityInformationFieldExtPresent(v *ULCPSecurityInformation) *[]bool {
	return &v.extPresent
}
func BridgeULCPSecurityInformationFieldExtWire(v *ULCPSecurityInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeULCPSecurityInformationFieldIEExtensionsIndef(v *ULCPSecurityInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeULCPSecurityInformationFieldPerExtPadding(v *ULCPSecurityInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeULCPSecurityInformationFieldPerPadding(v *ULCPSecurityInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeULCPSecurityInformationFieldReceived(v *ULCPSecurityInformation) *bool { return &v.received }
func BridgeULCPSecurityInformationFieldReceivedAbsolute(v *ULCPSecurityInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeULCPSecurityInformationFieldReceivedBytes(v *ULCPSecurityInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeULCPSecurityInformationFieldReceivedLocation(v *ULCPSecurityInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeULCPSecurityInformationFieldReplay(v *ULCPSecurityInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeULCPSecurityInformationFieldStream(v *ULCPSecurityInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeULCPSecurityInformationFieldWithoutReplay(v *ULCPSecurityInformation) *bool {
	return &v.withoutReplay
}
func BridgeULCPSecurityInformationMethodMarshalAPERBudget(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERBudgetValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERChanged(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERChangedValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERLegacy(v *ULCPSecurityInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeULCPSecurityInformationMethodMarshalAPERNewValue(v *ULCPSecurityInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeULCPSecurityInformationMethodMarshalAPERPlanned(v *ULCPSecurityInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeULCPSecurityInformationMethodMarshalAPERTo(v *ULCPSecurityInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERFrom(v *ULCPSecurityInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERLegacy(v *ULCPSecurityInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeULCPSecurityInformationMethodUnmarshalAPERWithOptions(v *ULCPSecurityInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeULCPSecurityInformationValueCodecFieldCapture(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, aper.DecodeState) (ULCPSecurityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeULCPSecurityInformationValueCodecFieldCompare(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeULCPSecurityInformationValueCodecFieldContext(v *ULCPSecurityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULCPSecurityInformationValueCodecFieldDecode(v *ULCPSecurityInformationValueCodec) *func([]byte, aper.DecodeState) (ULCPSecurityInformation, error) {
	return &v.decode
}
func BridgeULCPSecurityInformationValueCodecFieldEncode(v *ULCPSecurityInformationValueCodec) *func(ULCPSecurityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULCPSecurityInformationValueCodecFieldPath(v *ULCPSecurityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeULCPSecurityInformationValueCodecMethodEncodeBudgetValue(v ULCPSecurityInformationValueCodec, a0 ULCPSecurityInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeULCPSecurityInformationValueCodecMethodEncodeChanged(v ULCPSecurityInformationValueCodec, a0 ULCPSecurityInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBCPRelocationIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 96:
		if value, ok := v.AsSTMSI(); ok {
			return value, true
		}
	case 100:
		if value, ok := v.AsEUTRANCGI(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsTAI(); ok {
			return value, true
		}
	case 254:
		if value, ok := v.AsULCPSecurityInformation(); ok {
			return value, true
		}
	case 339:
		if value, ok := v.AsLTENTNTAIInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ENBEarlyStatusTransferIEValue) Selected() (any, bool) {
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
	case 321:
		if value, ok := v.AsENBEarlyStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 352:
		if value, ok := v.AsBearersSubjectToDLDiscardingList(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *MMEEarlyStatusTransferIEValue) Selected() (any, bool) {
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
	case 321:
		if value, ok := v.AsENBEarlyStatusTransferTransparentContainer(); ok {
			return value, true
		}
	}
	return nil, false
}
