// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s47 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s47

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
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
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
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(v *s46.UEContextReleaseCommandIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.ULCPSecurityInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
	codec  s17.BearersSubjectToDLDiscardingListValueCodec
	inject func(s17.BearersSubjectToDLDiscardingList,

	) ENBEarlyStatusTransferTransparentContainerExtIEsValue

	get func(*ENBEarlyStatusTransferTransparentContainerExtIEsValue,

	) (*s17.BearersSubjectToDLDiscardingList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Codec() s17.BearersSubjectToDLDiscardingListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) New(value s17.BearersSubjectToDLDiscardingList,

) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding) Get(field *ENBEarlyStatusTransferTransparentContainerExtIEsExtField) (*s17.BearersSubjectToDLDiscardingList,

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
	codec  s36.STMSIValueCodec
	inject func(s36.STMSI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s36.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Codec() s36.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationSTMSIIEBinding) New(value s36.STMSI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeSTMSIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationSTMSIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s36.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationEUTRANCGIIEBinding binds EUTRANCGI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s20.EUTRANCGIValueCodec
	inject func(s20.EUTRANCGI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s20.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Codec() s20.EUTRANCGIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) New(value s20.EUTRANCGI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationEUTRANCGIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s20.EUTRANCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENBCPRelocationIndicationTAIIEBinding binds TAI to the ENBCPRelocationIndicationIEs object set of TS 36.413.
type ENBCPRelocationIndicationTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s41.TAIValueCodec
	inject func(s40.TAI,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s40.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Codec() s41.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationTAIIEBinding) New(value s40.TAI,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s41.BridgeTAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationTAIIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s40.TAI,

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
	codec  s22.LTENTNTAIInformationValueCodec
	inject func(s22.LTENTNTAIInformation,

	) ENBCPRelocationIndicationIEValue

	get func(*ENBCPRelocationIndicationIEValue,

	) (*s22.LTENTNTAIInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Codec() s22.LTENTNTAIInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) New(value s22.LTENTNTAIInformation,

) (ENBCPRelocationIndicationIEField, error) {
	if b.inject == nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBCPRelocationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBCPRelocationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBCPRelocationIndicationLTENTNTAIInformationIEBinding) Get(field *ENBCPRelocationIndicationIEField) (*s22.LTENTNTAIInformation,

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

// UESecurityCapabilitiesValueCodec is the concrete ValueCodec[UESecurityCapabilities].
type UESecurityCapabilitiesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UESecurityCapabilities,

		error)
	encode func(UESecurityCapabilities,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UESecurityCapabilities, aper.DecodeState,

	) (UESecurityCapabilities, aper.Snapshot,

	)
	compare func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UESecurityCapabilitiesValueCodec) New(value UESecurityCapabilities,

) (UESecurityCapabilitiesAPERValue, error) {
	if c.encode == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UESecurityCapabilitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UESecurityCapabilitiesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UESecurityCapabilitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UESecurityCapabilitiesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UESecurityCapabilitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UESecurityCapabilitiesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UESecurityCapabilitiesValueCodec) EncodeAPER(value UESecurityCapabilitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UESecurityCapabilitiesValueCodec) encodeBudgetValue(value UESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UESecurityCapabilitiesValueCodec) encodeChanged(value UESecurityCapabilities,

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

// UEContextReleaseCommandValueCodec is the concrete ValueCodec[UEContextReleaseCommand].
type UEContextReleaseCommandValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommand,

		error)
	encode func(UEContextReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommand, aper.DecodeState,

	) (UEContextReleaseCommand, aper.Snapshot,

	)
	compare func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandValueCodec) New(value UEContextReleaseCommand,

) (UEContextReleaseCommandAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandValueCodec) EncodeAPER(value UEContextReleaseCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandValueCodec) encodeBudgetValue(value UEContextReleaseCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandValueCodec) encodeChanged(value UEContextReleaseCommand,

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
func BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields s46.UEContextReleaseCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s46.BridgeUEContextReleaseCommandIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s46.BridgeUEContextReleaseCommandIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s46.BridgeUEContextReleaseCommandIEValueMethodRule(field.Value).Assignment
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
func BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields ENBCPRelocationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(fields ENBEarlyStatusTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ENBEarlyStatusTransferTransparentContainerExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
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
func BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields s14.UES1APIDPairExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UES1APIDPairExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.UES1APIDPairExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields s14.UESecurityCapabilitiesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UESecurityCapabilitiesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.UESecurityCapabilitiesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UESidelinkAggregateMaximumBitratesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields s14.ULCPSecurityInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.ULCPSecurityInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.ULCPSecurityInformationExtIEsIEContainer, len(fields))
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
	return ENBCPRelocationIndicationIEValueERABIEContainerListValueCodec{path: "ENBCPRelocationIndicationIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueERABIEContainerList, error) {
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
	return ENBEarlyStatusTransferIEValueERABIEContainerListValueCodec{path: "ENBEarlyStatusTransferIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueERABIEContainerList, error) {
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

// UEContextReleaseCommandIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueERABIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) s46.UEContextReleaseCommandIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextReleaseCommandIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s46.UEContextReleaseCommandIEValueERABIEContainerListValueCodec {
		sealed := s46.UEContextReleaseCommandIEValueERABIEContainerListValueCodec{}
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCommandIEValueERABIEContainerList"
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.UEContextReleaseCommandIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.UEContextReleaseCommandIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(&codec))(s46.UEContextReleaseCommandIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextReleaseCommandIEValueERABIEContainerList, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextReleaseCommandIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs}} codec of TS 36.413.
func ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.ENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTable) ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtFieldValueCodec{path: "ENBEarlyStatusTransferTransparentContainerExtIEsExtField", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtField, error) {
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

// UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable) s14.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
	}
	return func() s14.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
		sealed := s14.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldPath(&sealed) = "UESecurityCapabilitiesExtIEsExtField"
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UESecurityCapabilitiesExtIEsExtField, error) {
			var field s14.UESecurityCapabilitiesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESecurityCapabilitiesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.UESecurityCapabilitiesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.UESecurityCapabilitiesExtIEsExtField, options aper.DecodeState) (s14.UESecurityCapabilitiesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.UESecurityCapabilitiesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable) s14.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
	}
	return func() s14.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
		sealed := s14.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitratesExtIEsExtField"
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, error) {
			var field s14.UESidelinkAggregateMaximumBitratesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESidelinkAggregateMaximumBitratesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, options aper.DecodeState) (s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionFieldTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable) s14.ULCPSecurityInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s14.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
	}
	return func() s14.ULCPSecurityInformationExtIEsExtFieldValueCodec {
		sealed := s14.ULCPSecurityInformationExtIEsExtFieldValueCodec{}
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "ULCPSecurityInformationExtIEsExtField"
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ULCPSecurityInformationExtIEsExtField, error) {
			var field s14.ULCPSecurityInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "ULCPSecurityInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "ULCPSecurityInformationExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.ULCPSecurityInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.ULCPSecurityInformationExtIEsExtField, options aper.DecodeState) (s14.ULCPSecurityInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.ULCPSecurityInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return ENBEarlyStatusTransferTransparentContainerExtIEsExtContainerValueCodec{path: "ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferTransparentContainerExtIEsExtContainer, error) {
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

// UESecurityCapabilitiesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable, bounds aper.ListBounds) s14.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
		sealed := s14.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldPath(&sealed) = "UESecurityCapabilitiesExtIEsExtContainer"
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UESecurityCapabilitiesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UESecurityCapabilitiesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UESecurityCapabilitiesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESecurityCapabilitiesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtContainer")
			}
			return fields, nil
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.UESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.UESecurityCapabilitiesExtIEsExtContainer, options aper.DecodeState) (s14.UESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.UESecurityCapabilitiesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable, bounds aper.ListBounds) s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec {
		sealed := s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodec{}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitratesExtIEsExtContainer"
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UESidelinkAggregateMaximumBitratesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, options aper.DecodeState) (s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ULCPSecurityInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UL-CP-SecurityInformation-ExtIEs}} codec of TS 36.413.
func ULCPSecurityInformationExtIEsValueExtensionTableCodec(table s00.ULCPSecurityInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s14.ULCPSecurityInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeULCPSecurityInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s14.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.ULCPSecurityInformationExtIEsExtContainerValueCodec {
		sealed := s14.ULCPSecurityInformationExtIEsExtContainerValueCodec{}
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "ULCPSecurityInformationExtIEsExtContainer"
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ULCPSecurityInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.ULCPSecurityInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.ULCPSecurityInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.ULCPSecurityInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.ULCPSecurityInformationExtIEsExtContainer, options aper.DecodeState) (s14.ULCPSecurityInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.ULCPSecurityInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeULCPSecurityInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return ENBCPRelocationIndicationIEFieldValueCodec{path: "ENBCPRelocationIndicationIEField", decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEField, error) {
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
	return ENBEarlyStatusTransferIEFieldValueCodec{path: "ENBEarlyStatusTransferIEField", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEField, error) {
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
	return MMEEarlyStatusTransferIEFieldValueCodec{path: "MMEEarlyStatusTransferIEField", decode: func(data []byte, options aper.DecodeState) (MMEEarlyStatusTransferIEField, error) {
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

// UEContextReleaseCommandIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIEFieldTableCodec(table s00.UEContextReleaseCommandIEValueIETable) s46.UEContextReleaseCommandIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return s46.UEContextReleaseCommandIEFieldValueCodec{}
	}
	return func() s46.UEContextReleaseCommandIEFieldValueCodec {
		sealed := s46.UEContextReleaseCommandIEFieldValueCodec{}
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldPath(&sealed) = "UEContextReleaseCommandIEField"
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseCommandIEField, error) {
			var field s46.UEContextReleaseCommandIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEField")
			}
			return field, nil
		}
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldEncode(&sealed) = func(field s46.UEContextReleaseCommandIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s46.BridgeUEContextReleaseCommandIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldCapture(&sealed) = func(v s46.UEContextReleaseCommandIEField, options aper.DecodeState) (s46.UEContextReleaseCommandIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldCompare(&sealed) = func(v s46.UEContextReleaseCommandIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextReleaseCommandIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueIETableCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEContainerValueCodec {
	if !*s00.BridgeENBCPRelocationIndicationIEValueIETableFieldBound(&table) {
		return ENBCPRelocationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEContainerValueCodec{path: "ENBCPRelocationIndicationIEContainer", decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEContainer, error) {
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
	return ENBEarlyStatusTransferIEContainerValueCodec{path: "ENBEarlyStatusTransferIEContainer", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEContainer, error) {
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

// UEContextReleaseCommandIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIETableCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) s46.UEContextReleaseCommandIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return s46.UEContextReleaseCommandIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s46.UEContextReleaseCommandIEContainerValueCodec {
		sealed := s46.UEContextReleaseCommandIEContainerValueCodec{}
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldPath(&sealed) = "UEContextReleaseCommandIEContainer"
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseCommandIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.UEContextReleaseCommandIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.UEContextReleaseCommandIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEContainer")
			}
			return fields, nil
		}
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(&sealed) = func(fields s46.UEContextReleaseCommandIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s46.BridgeUEContextReleaseCommandIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldCapture(&sealed) = func(v s46.UEContextReleaseCommandIEContainer, options aper.DecodeState) (s46.UEContextReleaseCommandIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldCompare(&sealed) = func(v s46.UEContextReleaseCommandIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ENBCPRelocationIndicationIEs}} codec of TS 36.413.
func ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable) ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEValueProtocolErrorIEContainerListValueCodec{path: "ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolErrorIEContainerList, error) {
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
	return ENBEarlyStatusTransferIEValueProtocolErrorIEContainerListValueCodec{path: "ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolErrorIEContainerList, error) {
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

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCommandIEValueProtocolErrorIEContainerList"
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.UEContextReleaseCommandIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(&codec))(s46.UEContextReleaseCommandIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ENBCPRelocationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ENBCPRelocationIndicationIEValueProtocolIEContainerListCodec(table s00.ENBCPRelocationIndicationIEValueIETable, bounds aper.ListBounds) ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := ENBCPRelocationIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return ENBCPRelocationIndicationIEValueProtocolIEContainerListValueCodec{path: "ENBCPRelocationIndicationIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBCPRelocationIndicationIEValueProtocolIEContainerList, error) {
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
	return ENBEarlyStatusTransferIEValueProtocolIEContainerListValueCodec{path: "ENBEarlyStatusTransferIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (ENBEarlyStatusTransferIEValueProtocolIEContainerList, error) {
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

// UEContextReleaseCommandIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseCommand-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextReleaseCommandIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) s46.UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, bounds)
	if *s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(&codec) == nil {
		return s46.UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s46.UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec {
		sealed := s46.UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextReleaseCommandIEValueProtocolIEContainerList"
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s46.UEContextReleaseCommandIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s46.UEContextReleaseCommandIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s46.UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s46.BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(&codec))(s46.UEContextReleaseCommandIEContainer(value), fresh, budget)
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s46.UEContextReleaseCommandIEValueProtocolIEContainerList, options aper.DecodeState) (s46.UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s46.UEContextReleaseCommandIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s46.BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
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
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
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
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextReleaseCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseCommandIEValue].
type UEContextReleaseCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s46.UEContextReleaseCommandIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s46.UEContextReleaseCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v *s46.UEContextReleaseCommandIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s46.BridgeUEContextReleaseCommandIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s46.BridgeUEContextReleaseCommandIEFieldFieldReplay(v), *s46.BridgeUEContextReleaseCommandIEFieldFieldWithoutReplay(v))
}

// uES1APIDPairExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UES1APIDPairExtIEsValue].
type UES1APIDPairExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.UES1APIDPairExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.UES1APIDPairExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uESecurityCapabilitiesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESecurityCapabilitiesExtIEsValue].
type UESecurityCapabilitiesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.UESecurityCapabilitiesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.UESecurityCapabilitiesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(v *s14.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeUESecurityCapabilitiesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s14.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(v *s14.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeUESecurityCapabilitiesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s14.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}

// uESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESidelinkAggregateMaximumBitratesExtIEsValue].
type UESidelinkAggregateMaximumBitratesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.UESidelinkAggregateMaximumBitratesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.UESidelinkAggregateMaximumBitratesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(v *s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(v *s14.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}

// uLCPSecurityInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ULCPSecurityInformationExtIEsValue].
type ULCPSecurityInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.ULCPSecurityInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.ULCPSecurityInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeULCPSecurityInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s14.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeULCPSecurityInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s14.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeULCPSecurityInformationExtIEsValueCompareS1APProtocolExtensionField(v *s14.ULCPSecurityInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeULCPSecurityInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeULCPSecurityInformationExtIEsExtFieldFieldReplay(v), *s14.BridgeULCPSecurityInformationExtIEsExtFieldFieldWithoutReplay(v))
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

// UESecurityCapabilitiesAPERValue is the concrete APERValue[UESecurityCapabilities].
type UESecurityCapabilitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   UESecurityCapabilities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UESecurityCapabilitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UESecurityCapabilitiesAPERValue) WithoutReplay() UESecurityCapabilitiesAPERValue {
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

// UEContextReleaseCommandAPERValue is the concrete APERValue[UEContextReleaseCommand].
type UEContextReleaseCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandAPERValue) WithoutReplay() UEContextReleaseCommandAPERValue {
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
func BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(fields s14.UES1APIDPairExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeUES1APIDPairExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(fields s14.UESecurityCapabilitiesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeUESecurityCapabilitiesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APIEContainer(fields s14.UESidelinkAggregateMaximumBitratesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeULCPSecurityInformationExtIEsValueValidateS1APIEContainer(fields s14.ULCPSecurityInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeULCPSecurityInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeULCPSecurityInformationExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(v *s46.UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(v *s46.UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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
func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(v *s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(v *s46.UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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
func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(v *s46.UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(v *s46.UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(v *s46.UEContextReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v, s)
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
	s25.BridgeCaptureS1APActivatedCellsList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APActivatedCellsListComplete(v *ActivatedCellsListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APActivatedCellsList(&v.Value, s)
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
	s08.BridgeCompareS1APBPLMNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APBearersSubjectToDLDiscardingListComplete(v *BearersSubjectToDLDiscardingListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s25.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v.Value, s)
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
					s36.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s20.BridgeCaptureS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s40.BridgeCaptureS1APTAI(v.rowTAI, s)
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
					s22.BridgeCaptureS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s36.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(100):
			{
				f := s.Begin()
				s.Bool(v.rowEUTRANCGI == nil)
				if v.rowEUTRANCGI != nil {
					s20.BridgeCompareS1APEUTRANCGI(v.rowEUTRANCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(67):
			{
				f := s.Begin()
				s.Bool(v.rowTAI == nil)
				if v.rowTAI != nil {
					s40.BridgeCompareS1APTAI(v.rowTAI, s)
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
					s22.BridgeCompareS1APLTENTNTAIInformation(v.rowLTENTNTAIInformation, s)
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
	s25.BridgeCaptureS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
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
	s25.BridgeCompareS1APBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, s)
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
					s25.BridgeCaptureS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s25.BridgeCompareS1APBearersSubjectToDLDiscardingList(v.rowBearersSubjectToDLDiscardingList, s)
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
func BridgeCaptureS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s46.BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s00.BridgeCaptureS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s02.BridgeCompareS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v *UESidelinkAggregateMaximumBitrate, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APBitRate(&v.UESidelinkAggregateMaximumBitRate, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s08.BridgeCompareS1APULNASMAC(&v.UlNASMAC, s)
	s08.BridgeCompareS1APULNASCount(&v.UlNASCount, s)
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
	BearersSubjectToEarlyStatusTransferList      s17.BearersSubjectToEarlyStatusTransferList                  `asn1:"tag:0,context,implicit"`
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

// UESecurityCapabilities represents the ASN.1 type UESecurityCapabilities (SEQUENCE).
type UESecurityCapabilities struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	EncryptionAlgorithms          s00.EncryptionAlgorithms                     `asn1:"tag:0,context,implicit"`
	IntegrityProtectionAlgorithms s00.IntegrityProtectionAlgorithms            `asn1:"tag:1,context,implicit"`
	IEExtensions                  s14.UESecurityCapabilitiesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                         `asn1:"-" json:"-"`
	extCount                      int64                                        `asn1:"-" json:"-"`
	extPresent                    []bool                                       `asn1:"-" json:"-"`
	extData                       [][]byte                                     `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
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
	IEExtensions                      s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	IEExtensions      s14.ULCPSecurityInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
	Value            s17.BearersSubjectToDLDiscardingList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *BearersSubjectToDLDiscardingListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BearersSubjectToDLDiscardingList from APER format.
func (v *BearersSubjectToDLDiscardingListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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

// UnmarshalAPERBearersSubjectToDLDiscardingListFrom decodes a BearersSubjectToDLDiscardingList list from bb.
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListFrom(bb *aper.BitBuffer) (s17.BearersSubjectToDLDiscardingList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue
	if err := BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERBearersSubjectToDLDiscardingListInto(v *s25.BridgeAsn1cAPERBearersSubjectToDLDiscardingListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s17.BearersSubjectToDLDiscardingList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s17.BearersSubjectToDLDiscardingItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s17.BridgeBearersSubjectToDLDiscardingItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := s16.BridgeMarshalAPERBPLMNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes BPLMNs from APER format.
func (v *BPLMNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1190
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
	if err := aper.EncodeCollection(bb, int64(len(v.BearersSubjectToEarlyStatusTransferList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList)) || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(len(v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BearersSubjectToEarlyStatusTransferList[fragmentOffset_bearerssubjecttoearlystatustransferlist : fragmentOffset_bearerssubjecttoearlystatustransferlist+fragmentLength_bearerssubjecttoearlystatustransferlist] {
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENBEarlyStatusTransferTransparentContainer from APER format.
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENBEarlyStatusTransferTransparentContainer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransferTransparentContainer{}
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
	toleranceMark_bearerssubjecttoearlystatustransferlist := bb.EnterComponent("BearersSubjectToEarlyStatusTransferList")
	v.BearersSubjectToEarlyStatusTransferList = make(s17.BearersSubjectToEarlyStatusTransferList, 0)
	_, errCollection_bearerssubjecttoearlystatustransferlist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_bearerssubjecttoearlystatustransferlist, fragmentLength_bearerssubjecttoearlystatustransferlist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist < 0 || fragmentLength_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1) || fragmentOffset_bearerssubjecttoearlystatustransferlist > int64(^uint(0)>>1)-fragmentLength_bearerssubjecttoearlystatustransferlist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bearerssubjecttoearlystatustransferlist; i++ {
			var elem s17.BearersSubjectToEarlyStatusTransferItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_bearerssubjecttoearlystatustransferlist + i)
			if err := s17.BridgeBearersSubjectToEarlyStatusTransferItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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

// MarshalAPER encodes UESecurityCapabilities to APER format.
func (v *UESecurityCapabilities) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UESecurityCapabilities) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.EncryptionAlgorithms.Bytes, v.EncryptionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding encryptionAlgorithms: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.IntegrityProtectionAlgorithms.Bytes, v.IntegrityProtectionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionAlgorithms: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESecurityCapabilities from APER format.
func (v *UESecurityCapabilities) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UESecurityCapabilities) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	bb.EnterComponent("UESecurityCapabilities")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	padding, err := aper.CaptureFinalBits(bb, "UESecurityCapabilities")
	if err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	v.perPadding = padding
	return nil
}
func (v *UESecurityCapabilities) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESecurityCapabilities{}
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
	bsBytes_encryptionalgorithms, bsBitLen_encryptionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EncryptionAlgorithms")
	}
	v.EncryptionAlgorithms = runtime.BitString{Bytes: bsBytes_encryptionalgorithms, BitLength: bsBitLen_encryptionalgorithms}
	bsBytes_integrityprotectionalgorithms, bsBitLen_integrityprotectionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionAlgorithms")
	}
	v.IntegrityProtectionAlgorithms = runtime.BitString{Bytes: bsBytes_integrityprotectionalgorithms, BitLength: bsBitLen_integrityprotectionalgorithms}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s14.UESecurityCapabilitiesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.UESecurityCapabilitiesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.UESidelinkAggregateMaximumBitRate), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(10000000000), false); err != nil {
		return fmt.Errorf("encoding uESidelinkAggregateMaximumBitRate: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESidelinkAggregateMaximumBitrate from APER format.
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UESidelinkAggregateMaximumBitrate) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESidelinkAggregateMaximumBitrate{}
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
	val_uesidelinkaggregatemaximumbitrate, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(10000000000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitRate")
	}
	v.UESidelinkAggregateMaximumBitRate = s00.BitRate(val_uesidelinkaggregatemaximumbitrate)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s14.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.UESidelinkAggregateMaximumBitratesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ULCPSecurityInformation from APER format.
func (v *ULCPSecurityInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ULCPSecurityInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ULCPSecurityInformation{}
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
		tmp_ieextensions := make(s14.ULCPSecurityInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.ULCPSecurityInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeULCPSecurityInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *BPLMNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BPLMNsComplete", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "BearersSubjectToDLDiscardingListComplete", v.receivedLocation, v.perPadding)
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
func (v *ENBEarlyStatusTransferTransparentContainer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBEarlyStatusTransferTransparentContainer", v.receivedLocation, v.perPadding)
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
func (v *UESecurityCapabilities) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UESecurityCapabilities) WithoutReplay() UESecurityCapabilities {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UESecurityCapabilities
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESidelinkAggregateMaximumBitrate", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ULCPSecurityInformation", v.receivedLocation, v.perPadding)
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
func (v *UESecurityCapabilities) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UESecurityCapabilities) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UESecurityCapabilities) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
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
	if err := s16.BridgeMarshalAPERBPLMNsTo(v.Value, bb, fresh); err != nil {
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
	if err := s30.BridgeMarshalAPERBearersSubjectToDLDiscardingListTo(v.Value, bb, fresh); err != nil {
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
func (v *UESecurityCapabilities) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UESecurityCapabilities")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UESecurityCapabilities) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UESecurityCapabilities")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UESecurityCapabilities")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UESecurityCapabilities) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
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
func (v *UESecurityCapabilities) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UESecurityCapabilities) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UESecurityCapabilities) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UESecurityCapabilities
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUESecurityCapabilities(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UESecurityCapabilities{}
		return report, aper.OperationError(err, "UESecurityCapabilities")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UESecurityCapabilities")
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

// MarshalAPERBearersSubjectToDLDiscardingList encodes a complete named list.
func MarshalAPERBearersSubjectToDLDiscardingList(v BearersSubjectToDLDiscardingListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERBPLMNs encodes a complete named list.
func MarshalAPERBPLMNs(v BPLMNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERBearersSubjectToDLDiscardingList decodes a complete named list.
func UnmarshalAPERBearersSubjectToDLDiscardingList(data []byte, options ...aper.DecodeOption) (BearersSubjectToDLDiscardingListComplete, aper.DecodeReport, error) {
	var v BearersSubjectToDLDiscardingListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERBPLMNs decodes a complete named list.
func UnmarshalAPERBPLMNs(data []byte, options ...aper.DecodeOption) (BPLMNsComplete, aper.DecodeReport, error) {
	var v BPLMNsComplete
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

// UEContextReleaseCommand represents the ASN.1 type UEContextReleaseCommand (SEQUENCE).
type UEContextReleaseCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s46.UEContextReleaseCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
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

// UnmarshalAPER decodes ENBEarlyStatusTransfer from APER format.
func (v *ENBEarlyStatusTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENBEarlyStatusTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBEarlyStatusTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBEarlyStatusTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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

// MarshalAPER encodes UEContextReleaseCommand to APER format.
func (v *UEContextReleaseCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s46.BridgeUEContextReleaseCommandIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextReleaseCommand from APER format.
func (v *UEContextReleaseCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *UEContextReleaseCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	bb.EnterComponent("UEContextReleaseCommand")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	v.perPadding = padding
	return nil
}
func (v *UEContextReleaseCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCommand{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s46.UEContextReleaseCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s46.UEContextReleaseCommandIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s46.BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UnmarshalAPER decodes ENBCPRelocationIndication from APER format.
func (v *ENBCPRelocationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENBCPRelocationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBCPRelocationIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ENBCPRelocationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
func (v *ENBCPRelocationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBCPRelocationIndication", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENBEarlyStatusTransfer", v.receivedLocation, v.perPadding)
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
func (v *UEContextReleaseCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseCommand) WithoutReplay() UEContextReleaseCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseCommand
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
func (v *UEContextReleaseCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
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
func (v *UEContextReleaseCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseCommand")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseCommand) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseCommand")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseCommand")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
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
func (v *UEContextReleaseCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextReleaseCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseCommand
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseCommand{}
		return report, aper.OperationError(err, "UEContextReleaseCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseCommand")
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
	Value            s16.ActivatedCellsList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ActivatedCellsListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ActivatedCellsList from APER format.
func (v *ActivatedCellsListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
func BridgeUnmarshalAPERActivatedCellsListFrom(bb *aper.BitBuffer) (s16.ActivatedCellsList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s25.BridgeAsn1cAPERActivatedCellsListListValue
	if err := BridgeUnmarshalAPERActivatedCellsListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERActivatedCellsListInto(v *s25.BridgeAsn1cAPERActivatedCellsListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s16.ActivatedCellsList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s16.ActivatedCellsListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s16.BridgeActivatedCellsListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ActivatedCellsListComplete", v.receivedLocation, v.perPadding)
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
	if err := s30.BridgeMarshalAPERActivatedCellsListTo(v.Value, bb, fresh); err != nil {
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

// MarshalAPERActivatedCellsList encodes a complete named list.
func MarshalAPERActivatedCellsList(v ActivatedCellsListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
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
	rowBearersSubjectToDLDiscardingList *s17.BearersSubjectToDLDiscardingList
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
func (v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) AsBearersSubjectToDLDiscardingList() (*s17.BearersSubjectToDLDiscardingList, bool) {
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
	rowSTMSI                   *s36.STMSI
	rowEUTRANCGI               *s20.EUTRANCGI
	rowTAI                     *s40.TAI
	rowULCPSecurityInformation *ULCPSecurityInformation
	rowLTENTNTAIInformation    *s22.LTENTNTAIInformation
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
func (v *ENBCPRelocationIndicationIEValue) AsSTMSI() (*s36.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsEUTRANCGI() (*s20.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of ENBCPRelocationIndicationIEValue and reports whether that alternative is active.
func (v *ENBCPRelocationIndicationIEValue) AsTAI() (*s40.TAI, bool) {
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
func (v *ENBCPRelocationIndicationIEValue) AsLTENTNTAIInformation() (*s22.LTENTNTAIInformation, bool) {
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
	case s00.ProtocolIEID(96):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s36.STMSI
		child := scope
		if err := s36.BridgeSTMSIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "STMSI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "STMSI")
		if err != nil {
			return out, err
		}
		*s36.BridgeSTMSIFieldPerPadding(&value) = padding
		*s36.BridgeSTMSIFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeSTMSIFieldReceivedBytes(&value))
		*s36.BridgeSTMSIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSTMSI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(100):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.EUTRANCGI
		child := scope
		if err := s20.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "EUTRANCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANCGI")
		if err != nil {
			return out, err
		}
		*s20.BridgeEUTRANCGIFieldPerPadding(&value) = padding
		*s20.BridgeEUTRANCGIFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeEUTRANCGIFieldReceivedBytes(&value))
		*s20.BridgeEUTRANCGIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowEUTRANCGI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(67):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s40.TAI
		child := scope
		if err := s40.BridgeTAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TAI")
		if err != nil {
			return out, err
		}
		*s40.BridgeTAIFieldPerPadding(&value) = padding
		*s40.BridgeTAIFieldReceived(&value) = true
		raw.RetainContents(s40.BridgeTAIFieldReceivedBytes(&value))
		*s40.BridgeTAIFieldReceivedLocation(&value) = raw.ContentLocation()
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
		var value s22.LTENTNTAIInformation
		child := scope
		if err := s22.BridgeLTENTNTAIInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "LTENTNTAIInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LTENTNTAIInformation")
		if err != nil {
			return out, err
		}
		*s22.BridgeLTENTNTAIInformationFieldPerPadding(&value) = padding
		*s22.BridgeLTENTNTAIInformationFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeLTENTNTAIInformationFieldReceivedBytes(&value))
		*s22.BridgeLTENTNTAIInformationFieldReceivedLocation(&value) = raw.ContentLocation()
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s36.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
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
		candidate, err := s20.BridgeEUTRANCGIMethodMarshalAPERBudget(v.rowEUTRANCGI, budget, fresh)
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
		candidate, err := s40.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
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
		candidate, err := s22.BridgeLTENTNTAIInformationMethodMarshalAPERBudget(v.rowLTENTNTAIInformation, budget, fresh)
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
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
	return ENBEarlyStatusTransferTransparentContainerExtIEsBearersSubjectToDLDiscardingListExtBinding{info: t.infoBearersSubjectToDLDiscardingList(), codec: func() s17.BearersSubjectToDLDiscardingListValueCodec {
		sealed := s17.BearersSubjectToDLDiscardingListValueCodec{}
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldPath(&sealed) = "BearersSubjectToDLDiscardingList"
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.BearersSubjectToDLDiscardingList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("BearersSubjectToDLDiscardingList")
			var zero ENBEarlyStatusTransferTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(352), raw)
			if err != nil {
				var empty s17.BearersSubjectToDLDiscardingList
				return empty, runtime.WrapDecodePath(err, "BearersSubjectToDLDiscardingList")
			}
			value, ok := decoded.AsBearersSubjectToDLDiscardingList()
			if !ok {
				var empty s17.BearersSubjectToDLDiscardingList
				return empty, fmt.Errorf("binding ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs.id-Bearers-SubjectToDLDiscardingList: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldEncode(&sealed) = func(value s17.BearersSubjectToDLDiscardingList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCapture(&sealed) = func(v s17.BearersSubjectToDLDiscardingList, options aper.DecodeState) (s17.BearersSubjectToDLDiscardingList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APBearersSubjectToDLDiscardingList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldCompare(&sealed) = func(v s17.BearersSubjectToDLDiscardingList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APBearersSubjectToDLDiscardingList(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeBearersSubjectToDLDiscardingListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BearersSubjectToDLDiscardingList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.BearersSubjectToDLDiscardingList) ENBEarlyStatusTransferTransparentContainerExtIEsValue {
			return ENBEarlyStatusTransferTransparentContainerExtIEsValue{id: s00.ProtocolIEID(352), rowBearersSubjectToDLDiscardingList: &value}
		}, get: func(value *ENBEarlyStatusTransferTransparentContainerExtIEsValue) (*s17.BearersSubjectToDLDiscardingList, bool) {
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
	return ENBCPRelocationIndicationSTMSIIEBinding{info: t.infoSTMSI(), codec: func() s36.STMSIValueCodec {
		sealed := s36.STMSIValueCodec{}
		*s36.BridgeSTMSIValueCodecFieldPath(&sealed) = "STMSI"
		*s36.BridgeSTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.STMSI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s36.STMSI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("STMSI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(96), raw)
			if err != nil {
				var empty s36.STMSI
				return empty, runtime.WrapDecodePath(err, "STMSI")
			}
			value, ok := decoded.AsSTMSI()
			if !ok {
				var empty s36.STMSI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-S-TMSI: no selected value")
			}
			return *value, nil
		}
		*s36.BridgeSTMSIValueCodecFieldEncode(&sealed) = func(value s36.STMSI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}).encodeFresh(fresh, budget)
		}
		*s36.BridgeSTMSIValueCodecFieldCapture(&sealed) = func(v s36.STMSI, options aper.DecodeState) (s36.STMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APSTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s36.BridgeSTMSIValueCodecFieldCompare(&sealed) = func(v s36.STMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APSTMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeSTMSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:STMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s36.STMSI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(96), rowSTMSI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s36.STMSI, bool) { return value.AsSTMSI() }}
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
	return ENBCPRelocationIndicationEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s20.EUTRANCGIValueCodec {
		sealed := s20.EUTRANCGIValueCodec{}
		*s20.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s20.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s20.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s20.EUTRANCGI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s20.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeEUTRANCGIValueCodecFieldCapture(&sealed) = func(v s20.EUTRANCGI, options aper.DecodeState) (s20.EUTRANCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s20.BridgeCaptureS1APEUTRANCGI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeEUTRANCGIValueCodecFieldCompare(&sealed) = func(v s20.EUTRANCGI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APEUTRANCGI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeEUTRANCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCGI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.EUTRANCGI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s20.EUTRANCGI, bool) { return value.AsEUTRANCGI() }}
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
	return ENBCPRelocationIndicationTAIIEBinding{info: t.infoTAI(), codec: func() s41.TAIValueCodec {
		sealed := s41.TAIValueCodec{}
		*s41.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s41.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s40.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s40.TAI
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s41.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s40.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
		}
		*s41.BridgeTAIValueCodecFieldCapture(&sealed) = func(v s40.TAI, options aper.DecodeState) (s40.TAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APTAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s41.BridgeTAIValueCodecFieldCompare(&sealed) = func(v s40.TAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APTAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeTAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.TAI) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s40.TAI, bool) { return value.AsTAI() }}
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
	return ENBCPRelocationIndicationLTENTNTAIInformationIEBinding{info: t.infoLTENTNTAIInformation(), codec: func() s22.LTENTNTAIInformationValueCodec {
		sealed := s22.LTENTNTAIInformationValueCodec{}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldPath(&sealed) = "LTENTNTAIInformation"
		*s22.BridgeLTENTNTAIInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.LTENTNTAIInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero ENBCPRelocationIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s22.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
			}
			value, ok := decoded.AsLTENTNTAIInformation()
			if !ok {
				var empty s22.LTENTNTAIInformation
				return empty, fmt.Errorf("binding ENBCPRelocationIndicationIEs.id-LTE-NTN-TAI-Information: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldEncode(&sealed) = func(value s22.LTENTNTAIInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCapture(&sealed) = func(v s22.LTENTNTAIInformation, options aper.DecodeState) (s22.LTENTNTAIInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APLTENTNTAIInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldCompare(&sealed) = func(v s22.LTENTNTAIInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APLTENTNTAIInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeLTENTNTAIInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LTENTNTAIInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.LTENTNTAIInformation) ENBCPRelocationIndicationIEValue {
			return ENBCPRelocationIndicationIEValue{id: s00.ProtocolIEID(339), rowLTENTNTAIInformation: &value}
		}, get: func(value *ENBCPRelocationIndicationIEValue) (*s22.LTENTNTAIInformation, bool) {
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
func ActivatedCellsListCodec() s16.ActivatedCellsListValueCodec {
	return func() s16.ActivatedCellsListValueCodec {
		sealed := s16.ActivatedCellsListValueCodec{}
		*s16.BridgeActivatedCellsListValueCodecFieldPath(&sealed) = "ActivatedCellsList"
		*s16.BridgeActivatedCellsListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.ActivatedCellsList, error) {
			var complete ActivatedCellsListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s16.ActivatedCellsList
				return zero, err
			}
			return complete.Value, nil
		}
		*s16.BridgeActivatedCellsListValueCodecFieldEncode(&sealed) = func(value s16.ActivatedCellsList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ActivatedCellsListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s16.BridgeActivatedCellsListValueCodecFieldCapture(&sealed) = func(v s16.ActivatedCellsList, options aper.DecodeState) (s16.ActivatedCellsList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s25.BridgeCaptureS1APActivatedCellsList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s16.BridgeActivatedCellsListValueCodecFieldCompare(&sealed) = func(v s16.ActivatedCellsList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APActivatedCellsList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s16.BridgeActivatedCellsListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
			s08.BridgeCompareS1APBPLMNs(&v, &s)
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
func BearersSubjectToDLDiscardingListCodec() s17.BearersSubjectToDLDiscardingListValueCodec {
	return ENBEarlyStatusTransferTransparentContainerExtIEs().BearersSubjectToDLDiscardingList().Codec()
}

// ENBEarlyStatusTransferTransparentContainerCodec binds the complete APER value type.
func ENBEarlyStatusTransferTransparentContainerCodec() ENBEarlyStatusTransferTransparentContainerValueCodec {
	return ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Codec()
}

// STMSICodec binds the complete APER value type.
func STMSICodec() s36.STMSIValueCodec { return ENBCPRelocationIndicationIEs().STMSI().Codec() }

// TAICodec binds the complete APER value type.
func TAICodec() s41.TAIValueCodec { return ENBCPRelocationIndicationIEs().TAI().Codec() }

// ULCPSecurityInformationCodec binds the complete APER value type.
func ULCPSecurityInformationCodec() ULCPSecurityInformationValueCodec {
	return ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Codec()
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodMarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeBearersSubjectToDLDiscardingListCompleteMethodUnmarshalAPERLegacy(v *BearersSubjectToDLDiscardingListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENBCPRelocationIndicationFieldPerPadding(v *ENBCPRelocationIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeENBCPRelocationIndicationIEValueFieldId(v *ENBCPRelocationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBCPRelocationIndicationIEValueFieldIsOpaque(v *ENBCPRelocationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBCPRelocationIndicationIEValueFieldOpaque(v *ENBCPRelocationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBCPRelocationIndicationIEValueFieldRowENBUES1APID(v *ENBCPRelocationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBCPRelocationIndicationIEValueFieldRowEUTRANCGI(v *ENBCPRelocationIndicationIEValue) **s20.EUTRANCGI {
	return &v.rowEUTRANCGI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowLTENTNTAIInformation(v *ENBCPRelocationIndicationIEValue) **s22.LTENTNTAIInformation {
	return &v.rowLTENTNTAIInformation
}
func BridgeENBCPRelocationIndicationIEValueFieldRowSTMSI(v *ENBCPRelocationIndicationIEValue) **s36.STMSI {
	return &v.rowSTMSI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowTAI(v *ENBCPRelocationIndicationIEValue) **s40.TAI {
	return &v.rowTAI
}
func BridgeENBCPRelocationIndicationIEValueFieldRowULCPSecurityInformation(v *ENBCPRelocationIndicationIEValue) **ULCPSecurityInformation {
	return &v.rowULCPSecurityInformation
}
func BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v *ENBCPRelocationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERFrom(v *ENBCPRelocationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBCPRelocationIndicationMethodUnmarshalAPERWithOptions(v *ENBCPRelocationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeENBEarlyStatusTransferFieldPerPadding(v *ENBEarlyStatusTransfer) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *ENBEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
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
func BridgeENBEarlyStatusTransferIEValueFieldRowENBEarlyStatusTransferTransparentContainer(v *ENBEarlyStatusTransferIEValue) **ENBEarlyStatusTransferTransparentContainer {
	return &v.rowENBEarlyStatusTransferTransparentContainer
}
func BridgeENBEarlyStatusTransferIEValueFieldRowENBUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeENBEarlyStatusTransferIEValueFieldRowMMEUES1APID(v *ENBEarlyStatusTransferIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeENBEarlyStatusTransferIEValueMethodMatchesID(v ENBEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v *ENBEarlyStatusTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENBEarlyStatusTransferMethodUnmarshalAPERFrom(v *ENBEarlyStatusTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBEarlyStatusTransferMethodUnmarshalAPERWithOptions(v *ENBEarlyStatusTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueFieldRowBearersSubjectToDLDiscardingList(v *ENBEarlyStatusTransferTransparentContainerExtIEsValue) **s17.BearersSubjectToDLDiscardingList {
	return &v.rowBearersSubjectToDLDiscardingList
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
func BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEFieldMethodUnmarshalAPERFrom(v *MMEEarlyStatusTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeMMEEarlyStatusTransferIEValueFieldId(v *MMEEarlyStatusTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEEarlyStatusTransferIEValueFieldIsOpaque(v *MMEEarlyStatusTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEEarlyStatusTransferIEValueFieldOpaque(v *MMEEarlyStatusTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(v MMEEarlyStatusTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEEarlyStatusTransferIEValueMethodRule(v MMEEarlyStatusTransferIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeUEContextReleaseCommandFieldPerPadding(v *UEContextReleaseCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseCommandFieldReceived(v *UEContextReleaseCommand) *bool { return &v.received }
func BridgeUEContextReleaseCommandFieldReceivedAbsolute(v *UEContextReleaseCommand) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseCommandFieldReceivedBytes(v *UEContextReleaseCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseCommandFieldReceivedLocation(v *UEContextReleaseCommand) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERFrom(v *UEContextReleaseCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERWithOptions(v *UEContextReleaseCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseCommandValueCodecFieldCapture(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.DecodeState) (UEContextReleaseCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandValueCodecFieldCompare(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandValueCodecFieldContext(v *UEContextReleaseCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandValueCodecFieldDecode(v *UEContextReleaseCommandValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommand, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandValueCodecFieldEncode(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandValueCodecFieldPath(v *UEContextReleaseCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESecurityCapabilitiesFieldPerPadding(v *UESecurityCapabilities) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESecurityCapabilitiesFieldReceived(v *UESecurityCapabilities) *bool { return &v.received }
func BridgeUESecurityCapabilitiesFieldReceivedBytes(v *UESecurityCapabilities) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESecurityCapabilitiesFieldReceivedLocation(v *UESecurityCapabilities) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(v *UESecurityCapabilities, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUESecurityCapabilitiesValueCodecFieldCapture(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.DecodeState) (UESecurityCapabilities, aper.Snapshot) {
	return &v.capture
}
func BridgeUESecurityCapabilitiesValueCodecFieldCompare(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUESecurityCapabilitiesValueCodecFieldContext(v *UESecurityCapabilitiesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESecurityCapabilitiesValueCodecFieldDecode(v *UESecurityCapabilitiesValueCodec) *func([]byte, aper.DecodeState) (UESecurityCapabilities, error) {
	return &v.decode
}
func BridgeUESecurityCapabilitiesValueCodecFieldEncode(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUESecurityCapabilitiesValueCodecFieldPath(v *UESecurityCapabilitiesValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(v *UESidelinkAggregateMaximumBitrate) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceived(v *UESidelinkAggregateMaximumBitrate) *bool {
	return &v.received
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(v *UESidelinkAggregateMaximumBitrate) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(v *UESidelinkAggregateMaximumBitrate) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v *UESidelinkAggregateMaximumBitrate, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(v *UESidelinkAggregateMaximumBitrate, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
