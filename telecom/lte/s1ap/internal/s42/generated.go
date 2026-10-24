// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s42 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s42

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// DownlinkNASTransportIEContainer is the concrete ProtocolIEContainer[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEContainer []DownlinkNASTransportIEField

// DownlinkNASTransportIEField is the concrete ProtocolIEField[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         DownlinkNASTransportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEField) WithoutReplay() DownlinkNASTransportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *DownlinkNASTransportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *DownlinkNASTransportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *DownlinkNASTransportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkNASTransportIEField{}
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
	var zero DownlinkNASTransportIEValue

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

// UEContextReleaseRequestIEContainer is the concrete ProtocolIEContainer[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEContainer []UEContextReleaseRequestIEField

// UEContextReleaseRequestIEField is the concrete ProtocolIEField[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextReleaseRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEField) WithoutReplay() UEContextReleaseRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextReleaseRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextReleaseRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextReleaseRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseRequestIEField{}
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
	var zero UEContextReleaseRequestIEValue

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

// PWSFailureIndicationIEContainer is the concrete ProtocolIEContainer[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEContainer []PWSFailureIndicationIEField

// PWSFailureIndicationIEField is the concrete ProtocolIEField[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PWSFailureIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEField) WithoutReplay() PWSFailureIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PWSFailureIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PWSFailureIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *PWSFailureIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PWSFailureIndicationIEField{}
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
	var zero PWSFailureIndicationIEValue

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
func BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEContainer(v *DownlinkNASTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEContainer(v *DownlinkNASTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionContainer(v *HandoverRestrictionListExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionContainer(v *HandoverRestrictionListExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEContainer(v *PWSFailureIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSFailureIndicationIEValueCompareS1APProtocolIEContainer(v *PWSFailureIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEContainer(v *UEContextReleaseRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEContainer(v *UEContextReleaseRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRestrictionListExtIEsExtContainer is the concrete ProtocolExtensionContainer[HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsExtContainer []HandoverRestrictionListExtIEsExtField

// HandoverRestrictionListExtIEsExtField is the concrete ProtocolExtensionField[HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue HandoverRestrictionListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRestrictionListExtIEsExtField) WithoutReplay() HandoverRestrictionListExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverRestrictionListExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverRestrictionListExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverRestrictionListExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRestrictionListExtIEsExtField{}
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
	var zero HandoverRestrictionListExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding is the concrete ExtensionBinding[NRrestrictioninEPSasSecondaryRAT, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.NRrestrictioninEPSasSecondaryRATValueCodec
	inject func(s00.NRrestrictioninEPSasSecondaryRAT,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s00.NRrestrictioninEPSasSecondaryRAT,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) Codec() s01.NRrestrictioninEPSasSecondaryRATValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) New(value s00.NRrestrictioninEPSasSecondaryRAT,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s00.NRrestrictioninEPSasSecondaryRAT,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding is the concrete ExtensionBinding[UnlicensedSpectrumRestriction, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.UnlicensedSpectrumRestrictionValueCodec
	inject func(s00.UnlicensedSpectrumRestriction,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s00.UnlicensedSpectrumRestriction,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) Codec() s02.UnlicensedSpectrumRestrictionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) New(value s00.UnlicensedSpectrumRestriction,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s00.UnlicensedSpectrumRestriction,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding is the concrete ExtensionBinding[CNTypeRestrictions, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding struct {
	info   s00.ExtensionInfo
	codec  s14.CNTypeRestrictionsValueCodec
	inject func(s14.CNTypeRestrictions,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s14.CNTypeRestrictions,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) Codec() s14.CNTypeRestrictionsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) New(value s14.CNTypeRestrictions,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCNTypeRestrictionsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s14.CNTypeRestrictions,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding is the concrete ExtensionBinding[NRrestrictionin5GS, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.NRrestrictionin5GSValueCodec
	inject func(s00.NRrestrictionin5GS,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s00.NRrestrictionin5GS,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) Codec() s01.NRrestrictionin5GSValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) New(value s00.NRrestrictionin5GS,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNRrestrictionin5GSValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s00.NRrestrictionin5GS,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverRestrictionListExtIEsPLMNidentityExtBinding is the concrete ExtensionBinding[PLMNidentity, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsPLMNidentityExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.PLMNidentityValueCodec
	inject func(s00.PLMNidentity,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s00.PLMNidentity,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsPLMNidentityExtBinding) Info() s00.ExtensionInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsPLMNidentityExtBinding) Codec() s01.PLMNidentityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsPLMNidentityExtBinding) New(value s00.PLMNidentity,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePLMNidentityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsPLMNidentityExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s00.PLMNidentity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// HandoverRestrictionListExtIEsRATRestrictionsExtBinding is the concrete ExtensionBinding[RATRestrictions, HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsRATRestrictionsExtBinding struct {
	info   s00.ExtensionInfo
	codec  s20.RATRestrictionsValueCodec
	inject func(s20.RATRestrictions,

	) HandoverRestrictionListExtIEsValue

	get func(*HandoverRestrictionListExtIEsValue,

	) (*s20.RATRestrictions,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRestrictionListExtIEsRATRestrictionsExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b HandoverRestrictionListExtIEsRATRestrictionsExtBinding) Codec() s20.RATRestrictionsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverRestrictionListExtIEsRATRestrictionsExtBinding) New(value s20.RATRestrictions,

) (HandoverRestrictionListExtIEsExtField, error) {
	if b.inject == nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeRATRestrictionsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRestrictionListExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRestrictionListExtIEsRATRestrictionsExtBinding) Get(field *HandoverRestrictionListExtIEsExtField) (*s20.RATRestrictions,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// DownlinkNASTransportMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, DownlinkNASTransportIEValue].
type DownlinkNASTransportMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportMMEUES1APIDIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, DownlinkNASTransportIEValue].
type DownlinkNASTransportENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportENBUES1APIDIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportNASPDUIEBinding is the concrete IEBinding[NASPDU, DownlinkNASTransportIEValue].
type DownlinkNASTransportNASPDUIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NASPDUValueCodec
	inject func(s00.NASPDU,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.NASPDU,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportNASPDUIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportNASPDUIEBinding) Codec() s01.NASPDUValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportNASPDUIEBinding) New(value s00.NASPDU,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNASPDUValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportNASPDUIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.NASPDU,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportHandoverRestrictionListIEBinding is the concrete IEBinding[HandoverRestrictionList, DownlinkNASTransportIEValue].
type DownlinkNASTransportHandoverRestrictionListIEBinding struct {
	info   s00.FieldInfo
	codec  HandoverRestrictionListValueCodec
	inject func(HandoverRestrictionList,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*HandoverRestrictionList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportHandoverRestrictionListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportHandoverRestrictionListIEBinding) Codec() HandoverRestrictionListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportHandoverRestrictionListIEBinding) New(value HandoverRestrictionList,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportHandoverRestrictionListIEBinding) Get(field *DownlinkNASTransportIEField) (*HandoverRestrictionList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRestrictionListValueCodec is the concrete ValueCodec[HandoverRestrictionList].
type HandoverRestrictionListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRestrictionList,

		error)
	encode func(HandoverRestrictionList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRestrictionList, aper.DecodeState,

	) (HandoverRestrictionList, aper.Snapshot,

	)
	compare func(HandoverRestrictionList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRestrictionListValueCodec) New(value HandoverRestrictionList,

) (HandoverRestrictionListAPERValue, error) {
	if c.encode == nil {
		return HandoverRestrictionListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRestrictionListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRestrictionListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRestrictionListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRestrictionListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRestrictionListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRestrictionListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRestrictionListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRestrictionListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRestrictionListValueCodec) EncodeAPER(value HandoverRestrictionListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRestrictionListValueCodec) encodeBudgetValue(value HandoverRestrictionList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRestrictionListValueCodec) encodeChanged(value HandoverRestrictionList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportSubscriberProfileIDforRFPIEBinding is the concrete IEBinding[SubscriberProfileIDforRFP, DownlinkNASTransportIEValue].
type DownlinkNASTransportSubscriberProfileIDforRFPIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SubscriberProfileIDforRFPValueCodec
	inject func(s00.SubscriberProfileIDforRFP,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.SubscriberProfileIDforRFP,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) Codec() s01.SubscriberProfileIDforRFPValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) New(value s00.SubscriberProfileIDforRFP,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.SubscriberProfileIDforRFP,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportSRVCCOperationPossibleIEBinding is the concrete IEBinding[SRVCCOperationPossible, DownlinkNASTransportIEValue].
type DownlinkNASTransportSRVCCOperationPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCOperationPossibleValueCodec
	inject func(s00.SRVCCOperationPossible,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.SRVCCOperationPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportSRVCCOperationPossibleIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportSRVCCOperationPossibleIEBinding) Codec() s01.SRVCCOperationPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportSRVCCOperationPossibleIEBinding) New(value s00.SRVCCOperationPossible,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportSRVCCOperationPossibleIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.SRVCCOperationPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportUERadioCapabilityIEBinding is the concrete IEBinding[UERadioCapability, DownlinkNASTransportIEValue].
type DownlinkNASTransportUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportUERadioCapabilityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportUERadioCapabilityIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding is the concrete IEBinding[DLNASPDUDeliveryAckRequest, DownlinkNASTransportIEValue].
type DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DLNASPDUDeliveryAckRequestValueCodec
	inject func(s00.DLNASPDUDeliveryAckRequest,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.DLNASPDUDeliveryAckRequest,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) Codec() s00.DLNASPDUDeliveryAckRequestValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) New(value s00.DLNASPDUDeliveryAckRequest,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.DLNASPDUDeliveryAckRequest,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportEnhancedCoverageRestrictedIEBinding is the concrete IEBinding[EnhancedCoverageRestricted, DownlinkNASTransportIEValue].
type DownlinkNASTransportEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportNRUESecurityCapabilitiesIEBinding is the concrete IEBinding[NRUESecurityCapabilities, DownlinkNASTransportIEValue].
type DownlinkNASTransportNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) Get(field *DownlinkNASTransportIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportCEModeBRestrictedIEBinding is the concrete IEBinding[CEModeBRestricted, DownlinkNASTransportIEValue].
type DownlinkNASTransportCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportCEModeBRestrictedIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportUECapabilityInfoRequestIEBinding is the concrete IEBinding[UECapabilityInfoRequest, DownlinkNASTransportIEValue].
type DownlinkNASTransportUECapabilityInfoRequestIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UECapabilityInfoRequestValueCodec
	inject func(s00.UECapabilityInfoRequest,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.UECapabilityInfoRequest,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportUECapabilityInfoRequestIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportUECapabilityInfoRequestIEBinding) Codec() s02.UECapabilityInfoRequestValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportUECapabilityInfoRequestIEBinding) New(value s00.UECapabilityInfoRequest,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUECapabilityInfoRequestValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportUECapabilityInfoRequestIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.UECapabilityInfoRequest,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportEndIndicationIEBinding is the concrete IEBinding[EndIndication, DownlinkNASTransportIEValue].
type DownlinkNASTransportEndIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EndIndicationValueCodec
	inject func(s00.EndIndication,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.EndIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportEndIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportEndIndicationIEBinding) Codec() s00.EndIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportEndIndicationIEBinding) New(value s00.EndIndication,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEndIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportEndIndicationIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.EndIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportPendingDataIndicationIEBinding is the concrete IEBinding[PendingDataIndication, DownlinkNASTransportIEValue].
type DownlinkNASTransportPendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportPendingDataIndicationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportPendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportPendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportPendingDataIndicationIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding is the concrete IEBinding[SubscriptionBasedUEDifferentiationInfo, DownlinkNASTransportIEValue].
type DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s30.SubscriptionBasedUEDifferentiationInfo,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s30.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s30.SubscriptionBasedUEDifferentiationInfo,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *DownlinkNASTransportIEField) (*s30.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding is the concrete IEBinding[AdditionalRRMPriorityIndex, DownlinkNASTransportIEValue].
type DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportUERadioCapabilityIDIEBinding is the concrete IEBinding[UERadioCapabilityID, DownlinkNASTransportIEValue].
type DownlinkNASTransportUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportUERadioCapabilityIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportUERadioCapabilityIDIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportMaskedIMEISVIEBinding is the concrete IEBinding[MaskedIMEISV, DownlinkNASTransportIEValue].
type DownlinkNASTransportMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportMaskedIMEISVIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportCoarseUELocationIEBinding is the concrete IEBinding[CoarseUELocation, DownlinkNASTransportIEValue].
type DownlinkNASTransportCoarseUELocationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CoarseUELocationValueCodec
	inject func(s00.CoarseUELocation,

	) DownlinkNASTransportIEValue

	get func(*DownlinkNASTransportIEValue,

	) (*s00.CoarseUELocation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b DownlinkNASTransportCoarseUELocationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b DownlinkNASTransportCoarseUELocationIEBinding) Codec() s00.CoarseUELocationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b DownlinkNASTransportCoarseUELocationIEBinding) New(value s00.CoarseUELocation,

) (DownlinkNASTransportIEField, error) {
	if b.inject == nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCoarseUELocationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return DownlinkNASTransportIEField{}, aper.OperationError(err, "Value.New")
	}
	return DownlinkNASTransportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b DownlinkNASTransportCoarseUELocationIEBinding) Get(field *DownlinkNASTransportIEField) (*s00.CoarseUELocation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSFailureIndicationPWSfailedECGIListIEBinding is the concrete IEBinding[PWSfailedECGIList, PWSFailureIndicationIEValue].
type PWSFailureIndicationPWSfailedECGIListIEBinding struct {
	info   s00.FieldInfo
	codec  s20.PWSfailedECGIListValueCodec
	inject func(s20.PWSfailedECGIList,

	) PWSFailureIndicationIEValue

	get func(*PWSFailureIndicationIEValue,

	) (*s20.PWSfailedECGIList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSFailureIndicationPWSfailedECGIListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSFailureIndicationPWSfailedECGIListIEBinding) Codec() s20.PWSfailedECGIListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSFailureIndicationPWSfailedECGIListIEBinding) New(value s20.PWSfailedECGIList,

) (PWSFailureIndicationIEField, error) {
	if b.inject == nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgePWSfailedECGIListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSFailureIndicationPWSfailedECGIListIEBinding) Get(field *PWSFailureIndicationIEField) (*s20.PWSfailedECGIList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSFailureIndicationGlobalENBIDIEBinding is the concrete IEBinding[GlobalENBID, PWSFailureIndicationIEValue].
type PWSFailureIndicationGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GlobalENBIDValueCodec
	inject func(s18.GlobalENBID,

	) PWSFailureIndicationIEValue

	get func(*PWSFailureIndicationIEValue,

	) (*s18.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSFailureIndicationGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSFailureIndicationGlobalENBIDIEBinding) Codec() s18.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PWSFailureIndicationGlobalENBIDIEBinding) New(value s18.GlobalENBID,

) (PWSFailureIndicationIEField, error) {
	if b.inject == nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSFailureIndicationGlobalENBIDIEBinding) Get(field *PWSFailureIndicationIEField) (*s18.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseRequestMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, UEContextReleaseRequestIEValue].
type UEContextReleaseRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) UEContextReleaseRequestIEValue

	get func(*UEContextReleaseRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (UEContextReleaseRequestIEField, error) {
	if b.inject == nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseRequestMMEUES1APIDIEBinding) Get(field *UEContextReleaseRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseRequestENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, UEContextReleaseRequestIEValue].
type UEContextReleaseRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) UEContextReleaseRequestIEValue

	get func(*UEContextReleaseRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (UEContextReleaseRequestIEField, error) {
	if b.inject == nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseRequestENBUES1APIDIEBinding) Get(field *UEContextReleaseRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseRequestCauseIEBinding is the concrete IEBinding[Cause, UEContextReleaseRequestIEValue].
type UEContextReleaseRequestCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) UEContextReleaseRequestIEValue

	get func(*UEContextReleaseRequestIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseRequestCauseIEBinding) New(value s14.Cause,

) (UEContextReleaseRequestIEField, error) {
	if b.inject == nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseRequestCauseIEBinding) Get(field *UEContextReleaseRequestIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseRequestGWContextReleaseIndicationIEBinding is the concrete IEBinding[GWContextReleaseIndication, UEContextReleaseRequestIEValue].
type UEContextReleaseRequestGWContextReleaseIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.GWContextReleaseIndicationValueCodec
	inject func(s00.GWContextReleaseIndication,

	) UEContextReleaseRequestIEValue

	get func(*UEContextReleaseRequestIEValue,

	) (*s00.GWContextReleaseIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestGWContextReleaseIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestGWContextReleaseIndicationIEBinding) Codec() s00.GWContextReleaseIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseRequestGWContextReleaseIndicationIEBinding) New(value s00.GWContextReleaseIndication,

) (UEContextReleaseRequestIEField, error) {
	if b.inject == nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeGWContextReleaseIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseRequestGWContextReleaseIndicationIEBinding) Get(field *UEContextReleaseRequestIEField) (*s00.GWContextReleaseIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding is the concrete IEBinding[SecondaryRATDataUsageReportList, UEContextReleaseRequestIEValue].
type UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) UEContextReleaseRequestIEValue

	get func(*UEContextReleaseRequestIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (UEContextReleaseRequestIEField, error) {
	if b.inject == nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) Get(field *UEContextReleaseRequestIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// DownlinkNASTransportValueCodec is the concrete ValueCodec[DownlinkNASTransport].
type DownlinkNASTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransport,

		error)
	encode func(DownlinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransport, aper.DecodeState,

	) (DownlinkNASTransport, aper.Snapshot,

	)
	compare func(DownlinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportValueCodec) New(value DownlinkNASTransport,

) (DownlinkNASTransportAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportValueCodec) EncodeAPER(value DownlinkNASTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportValueCodec) encodeBudgetValue(value DownlinkNASTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportValueCodec) encodeChanged(value DownlinkNASTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationValueCodec is the concrete ValueCodec[PWSFailureIndication].
type PWSFailureIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndication,

		error)
	encode func(PWSFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndication, aper.DecodeState,

	) (PWSFailureIndication, aper.Snapshot,

	)
	compare func(PWSFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationValueCodec) New(value PWSFailureIndication,

) (PWSFailureIndicationAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationValueCodec) EncodeAPER(value PWSFailureIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationValueCodec) encodeBudgetValue(value PWSFailureIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationValueCodec) encodeChanged(value PWSFailureIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestValueCodec is the concrete ValueCodec[UEContextReleaseRequest].
type UEContextReleaseRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequest,

		error)
	encode func(UEContextReleaseRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequest, aper.DecodeState,

	) (UEContextReleaseRequest, aper.Snapshot,

	)
	compare func(UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestValueCodec) New(value UEContextReleaseRequest,

) (UEContextReleaseRequestAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestValueCodec) EncodeAPER(value UEContextReleaseRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestValueCodec) encodeBudgetValue(value UEContextReleaseRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestValueCodec) encodeChanged(value UEContextReleaseRequest,

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
func BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(fields DownlinkNASTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(fields UEContextReleaseRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgePWSFailureIndicationIEValueValidateS1APIEContainer(fields PWSFailureIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeHandoverRestrictionListExtIEsValueValidateS1APExtensionContainer(fields HandoverRestrictionListExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[HandoverRestrictionListExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(HandoverRestrictionListExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeHandoverRestrictionListExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func DownlinkNASTransportIEValueERABIEContainerListCodec(table s00.DownlinkNASTransportIEValueIETable) DownlinkNASTransportIEValueERABIEContainerListValueCodec {
	codec := DownlinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return DownlinkNASTransportIEValueERABIEContainerListValueCodec{}
	}
	return DownlinkNASTransportIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkNASTransportIEValueERABIEContainerList(value), err
	}, encode: func(value DownlinkNASTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkNASTransportIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkNASTransportIEValueERABIEContainerList, options aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v DownlinkNASTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCompareS1APERABIEContainerList(&v, &s)
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
func PWSFailureIndicationIEValueERABIEContainerListCodec(table s00.PWSFailureIndicationIEValueIETable) PWSFailureIndicationIEValueERABIEContainerListValueCodec {
	codec := PWSFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSFailureIndicationIEValueERABIEContainerListValueCodec{}
	}
	return PWSFailureIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSFailureIndicationIEValueERABIEContainerList(value), err
	}, encode: func(value PWSFailureIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSFailureIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSFailureIndicationIEValueERABIEContainerList, options aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PWSFailureIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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
func UEContextReleaseRequestIEValueERABIEContainerListCodec(table s00.UEContextReleaseRequestIEValueIETable) UEContextReleaseRequestIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseRequestIEValueERABIEContainerListValueCodec{}
	}
	return UEContextReleaseRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseRequestIEValueERABIEContainerList(value), err
	}, encode: func(value UEContextReleaseRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseRequestIEValueERABIEContainerList, options aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCompareS1APERABIEContainerList(&v, &s)
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
func HandoverRestrictionListExtIEsValueExtensionFieldTableCodec(table s00.HandoverRestrictionListExtIEsValueExtensionTable) HandoverRestrictionListExtIEsExtFieldValueCodec {
	if !*s00.BridgeHandoverRestrictionListExtIEsValueExtensionTableFieldBound(&table) {
		return HandoverRestrictionListExtIEsExtFieldValueCodec{}
	}
	return HandoverRestrictionListExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRestrictionListExtIEsExtField, error) {
		var field HandoverRestrictionListExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field HandoverRestrictionListExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v HandoverRestrictionListExtIEsExtField, options aper.DecodeState) (HandoverRestrictionListExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v HandoverRestrictionListExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func HandoverRestrictionListExtIEsValueExtensionTableCodec(table s00.HandoverRestrictionListExtIEsValueExtensionTable, bounds aper.ListBounds) HandoverRestrictionListExtIEsExtContainerValueCodec {
	if !*s00.BridgeHandoverRestrictionListExtIEsValueExtensionTableFieldBound(&table) {
		return HandoverRestrictionListExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverRestrictionListExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRestrictionListExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRestrictionListExtIEsExtField
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
		if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
			return nil, err
		}
		return fields, nil
	},
		encode: func(fields HandoverRestrictionListExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v HandoverRestrictionListExtIEsExtContainer, options aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v HandoverRestrictionListExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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
func DownlinkNASTransportIEValueIEFieldTableCodec(table s00.DownlinkNASTransportIEValueIETable) DownlinkNASTransportIEFieldValueCodec {
	if !*s00.BridgeDownlinkNASTransportIEValueIETableFieldBound(&table) {
		return DownlinkNASTransportIEFieldValueCodec{}
	}
	return DownlinkNASTransportIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkNASTransportIEField, error) {
		var field DownlinkNASTransportIEField
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
	}, encode: func(field DownlinkNASTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v DownlinkNASTransportIEField, options aper.DecodeState) (DownlinkNASTransportIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v DownlinkNASTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEField(&v, &s)
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
func PWSFailureIndicationIEValueIEFieldTableCodec(table s00.PWSFailureIndicationIEValueIETable) PWSFailureIndicationIEFieldValueCodec {
	if !*s00.BridgePWSFailureIndicationIEValueIETableFieldBound(&table) {
		return PWSFailureIndicationIEFieldValueCodec{}
	}
	return PWSFailureIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSFailureIndicationIEField, error) {
		var field PWSFailureIndicationIEField
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
	}, encode: func(field PWSFailureIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PWSFailureIndicationIEField, options aper.DecodeState) (PWSFailureIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PWSFailureIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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
func UEContextReleaseRequestIEValueIEFieldTableCodec(table s00.UEContextReleaseRequestIEValueIETable) UEContextReleaseRequestIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseRequestIEValueIETableFieldBound(&table) {
		return UEContextReleaseRequestIEFieldValueCodec{}
	}
	return UEContextReleaseRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseRequestIEField, error) {
		var field UEContextReleaseRequestIEField
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
	}, encode: func(field UEContextReleaseRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEContextReleaseRequestIEField, options aper.DecodeState) (UEContextReleaseRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v UEContextReleaseRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEField(&v, &s)
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
func DownlinkNASTransportIEValueIETableCodec(table s00.DownlinkNASTransportIEValueIETable, bounds aper.ListBounds) DownlinkNASTransportIEContainerValueCodec {
	if !*s00.BridgeDownlinkNASTransportIEValueIETableFieldBound(&table) {
		return DownlinkNASTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return DownlinkNASTransportIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkNASTransportIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields DownlinkNASTransportIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field DownlinkNASTransportIEField
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
		encode: func(fields DownlinkNASTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v DownlinkNASTransportIEContainer, options aper.DecodeState) (DownlinkNASTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v DownlinkNASTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func PWSFailureIndicationIEValueIETableCodec(table s00.PWSFailureIndicationIEValueIETable, bounds aper.ListBounds) PWSFailureIndicationIEContainerValueCodec {
	if !*s00.BridgePWSFailureIndicationIEValueIETableFieldBound(&table) {
		return PWSFailureIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PWSFailureIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSFailureIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PWSFailureIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PWSFailureIndicationIEField
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
		encode: func(fields PWSFailureIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v PWSFailureIndicationIEContainer, options aper.DecodeState) (PWSFailureIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v PWSFailureIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePWSFailureIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func UEContextReleaseRequestIEValueIETableCodec(table s00.UEContextReleaseRequestIEValueIETable, bounds aper.ListBounds) UEContextReleaseRequestIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseRequestIEValueIETableFieldBound(&table) {
		return UEContextReleaseRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseRequestIEField
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
		encode: func(fields UEContextReleaseRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEContextReleaseRequestIEContainer, options aper.DecodeState) (UEContextReleaseRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UEContextReleaseRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func DownlinkNASTransportIEValueProtocolErrorIEContainerListCodec(table s00.DownlinkNASTransportIEValueIETable) DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := DownlinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkNASTransportIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value DownlinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkNASTransportIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkNASTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v DownlinkNASTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeDownlinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func PWSFailureIndicationIEValueProtocolErrorIEContainerListCodec(table s00.PWSFailureIndicationIEValueIETable) PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := PWSFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSFailureIndicationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value PWSFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSFailureIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSFailureIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PWSFailureIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgePWSFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func UEContextReleaseRequestIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseRequestIEValueIETable) UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value UEContextReleaseRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeUEContextReleaseRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func DownlinkNASTransportIEValueProtocolIEContainerListCodec(table s00.DownlinkNASTransportIEValueIETable, bounds aper.ListBounds) DownlinkNASTransportIEValueProtocolIEContainerListValueCodec {
	codec := DownlinkNASTransportIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return DownlinkNASTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return DownlinkNASTransportIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return DownlinkNASTransportIEValueProtocolIEContainerList(value), err
	}, encode: func(value DownlinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(DownlinkNASTransportIEContainer(value), fresh, budget)
	}, capture: func(v DownlinkNASTransportIEValueProtocolIEContainerList, options aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v DownlinkNASTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func PWSFailureIndicationIEValueProtocolIEContainerListCodec(table s00.PWSFailureIndicationIEValueIETable, bounds aper.ListBounds) PWSFailureIndicationIEValueProtocolIEContainerListValueCodec {
	codec := PWSFailureIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PWSFailureIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return PWSFailureIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSFailureIndicationIEValueProtocolIEContainerList(value), err
	}, encode: func(value PWSFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSFailureIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSFailureIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v PWSFailureIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSFailureIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func UEContextReleaseRequestIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseRequestIEValueIETable, bounds aper.ListBounds) UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return UEContextReleaseRequestIEValueProtocolIEContainerList(value), err
	}, encode: func(value UEContextReleaseRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseRequestIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseRequestIEValueProtocolIEContainerList, options aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v UEContextReleaseRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// downlinkNASTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) DownlinkNASTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (DownlinkNASTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEField(v *DownlinkNASTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEField(v *DownlinkNASTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// handoverRestrictionListExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) HandoverRestrictionListExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (HandoverRestrictionListExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionField(v *HandoverRestrictionListExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionField(v *HandoverRestrictionListExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// pWSFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PWSFailureIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PWSFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEField(v *PWSFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePWSFailureIndicationIEValueCompareS1APProtocolIEField(v *PWSFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextReleaseRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEContextReleaseRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEContextReleaseRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEField(v *UEContextReleaseRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEField(v *UEContextReleaseRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// HandoverRestrictionListAPERValue is the concrete APERValue[HandoverRestrictionList].
type HandoverRestrictionListAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverRestrictionList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRestrictionListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRestrictionListAPERValue) WithoutReplay() HandoverRestrictionListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportAPERValue is the concrete APERValue[DownlinkNASTransport].
type DownlinkNASTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   DownlinkNASTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportAPERValue) WithoutReplay() DownlinkNASTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationAPERValue is the concrete APERValue[PWSFailureIndication].
type PWSFailureIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PWSFailureIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationAPERValue) WithoutReplay() PWSFailureIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestAPERValue is the concrete APERValue[UEContextReleaseRequest].
type UEContextReleaseRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestAPERValue) WithoutReplay() UEContextReleaseRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRestrictionListExtIEsIEField is the concrete ProtocolIEField[HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         HandoverRestrictionListExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRestrictionListExtIEsIEField) WithoutReplay() HandoverRestrictionListExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *HandoverRestrictionListExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *HandoverRestrictionListExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *HandoverRestrictionListExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRestrictionListExtIEsIEField{}
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
	var zero HandoverRestrictionListExtIEsValue

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

// HandoverRestrictionListExtIEsIEContainer is the concrete ProtocolIEContainer[HandoverRestrictionListExtIEsValue].
type HandoverRestrictionListExtIEsIEContainer []HandoverRestrictionListExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeHandoverRestrictionListExtIEsValueValidateS1APIEContainer(fields HandoverRestrictionListExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// DownlinkNASTransportIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, error)
	encode  func(DownlinkNASTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, aper.Snapshot)
	compare func(DownlinkNASTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportIEValueERABIEContainerListValueCodec) New(value DownlinkNASTransportIEValueERABIEContainerList) (DownlinkNASTransportIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportIEValueERABIEContainerListValueCodec) EncodeAPER(value DownlinkNASTransportIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportIEValueERABIEContainerListValueCodec) encodeBudgetValue(value DownlinkNASTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportIEValueERABIEContainerListValueCodec) encodeChanged(value DownlinkNASTransportIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEValueERABIEContainerList is the concrete ERABIEContainerList[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEValueERABIEContainerList []DownlinkNASTransportIEValueProtocolIESingleContainer

func BridgeDownlinkNASTransportIEValueCaptureS1APERABIEContainerList(v *DownlinkNASTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNASTransportIEValueCompareS1APERABIEContainerList(v *DownlinkNASTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PWSFailureIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, error)
	encode  func(PWSFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(PWSFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationIEValueERABIEContainerListValueCodec) New(value PWSFailureIndicationIEValueERABIEContainerList) (PWSFailureIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value PWSFailureIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PWSFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value PWSFailureIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationIEValueERABIEContainerList is the concrete ERABIEContainerList[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEValueERABIEContainerList []PWSFailureIndicationIEValueProtocolIESingleContainer

func BridgePWSFailureIndicationIEValueCaptureS1APERABIEContainerList(v *PWSFailureIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSFailureIndicationIEValueCompareS1APERABIEContainerList(v *PWSFailureIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextReleaseRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, error)
	encode  func(UEContextReleaseRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestIEValueERABIEContainerListValueCodec) New(value UEContextReleaseRequestIEValueERABIEContainerList) (UEContextReleaseRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextReleaseRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextReleaseRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEValueERABIEContainerList []UEContextReleaseRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseRequestIEValueCaptureS1APERABIEContainerList(v *UEContextReleaseRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APERABIEContainerList(v *UEContextReleaseRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRestrictionListExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[HandoverRestrictionListExtIEsValue]].
type HandoverRestrictionListExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRestrictionListExtIEsExtField, error)
	encode  func(HandoverRestrictionListExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRestrictionListExtIEsExtField, aper.DecodeState) (HandoverRestrictionListExtIEsExtField, aper.Snapshot)
	compare func(HandoverRestrictionListExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRestrictionListExtIEsExtFieldValueCodec) New(value HandoverRestrictionListExtIEsExtField) (HandoverRestrictionListExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return HandoverRestrictionListExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRestrictionListExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRestrictionListExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRestrictionListExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRestrictionListExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRestrictionListExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRestrictionListExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRestrictionListExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRestrictionListExtIEsExtFieldValueCodec) EncodeAPER(value HandoverRestrictionListExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRestrictionListExtIEsExtFieldValueCodec) encodeBudgetValue(value HandoverRestrictionListExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRestrictionListExtIEsExtFieldValueCodec) encodeChanged(value HandoverRestrictionListExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRestrictionListExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[HandoverRestrictionListExtIEsValue]].
type HandoverRestrictionListExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, error)
	encode  func(HandoverRestrictionListExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRestrictionListExtIEsExtContainer, aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, aper.Snapshot)
	compare func(HandoverRestrictionListExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRestrictionListExtIEsExtContainerValueCodec) New(value HandoverRestrictionListExtIEsExtContainer) (HandoverRestrictionListExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return HandoverRestrictionListExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRestrictionListExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRestrictionListExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRestrictionListExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRestrictionListExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRestrictionListExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRestrictionListExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRestrictionListExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRestrictionListExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRestrictionListExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRestrictionListExtIEsExtContainerValueCodec) EncodeAPER(value HandoverRestrictionListExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverRestrictionListExtIEsExtContainerValueCodec) encodeBudgetValue(value HandoverRestrictionListExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRestrictionListExtIEsExtContainerValueCodec) encodeChanged(value HandoverRestrictionListExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransportIEField, error)
	encode  func(DownlinkNASTransportIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransportIEField, aper.DecodeState) (DownlinkNASTransportIEField, aper.Snapshot)
	compare func(DownlinkNASTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportIEFieldValueCodec) New(value DownlinkNASTransportIEField) (DownlinkNASTransportIEFieldAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportIEFieldValueCodec) EncodeAPER(value DownlinkNASTransportIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportIEFieldValueCodec) encodeBudgetValue(value DownlinkNASTransportIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportIEFieldValueCodec) encodeChanged(value DownlinkNASTransportIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndicationIEField, error)
	encode  func(PWSFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndicationIEField, aper.DecodeState) (PWSFailureIndicationIEField, aper.Snapshot)
	compare func(PWSFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationIEFieldValueCodec) New(value PWSFailureIndicationIEField) (PWSFailureIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationIEFieldValueCodec) EncodeAPER(value PWSFailureIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationIEFieldValueCodec) encodeBudgetValue(value PWSFailureIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationIEFieldValueCodec) encodeChanged(value PWSFailureIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequestIEField, error)
	encode  func(UEContextReleaseRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequestIEField, aper.DecodeState) (UEContextReleaseRequestIEField, aper.Snapshot)
	compare func(UEContextReleaseRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestIEFieldValueCodec) New(value UEContextReleaseRequestIEField) (UEContextReleaseRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestIEFieldValueCodec) EncodeAPER(value UEContextReleaseRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestIEFieldValueCodec) encodeBudgetValue(value UEContextReleaseRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestIEFieldValueCodec) encodeChanged(value UEContextReleaseRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransportIEContainer, error)
	encode  func(DownlinkNASTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransportIEContainer, aper.DecodeState) (DownlinkNASTransportIEContainer, aper.Snapshot)
	compare func(DownlinkNASTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportIEContainerValueCodec) New(value DownlinkNASTransportIEContainer) (DownlinkNASTransportIEContainerAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportIEContainerValueCodec) EncodeAPER(value DownlinkNASTransportIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportIEContainerValueCodec) encodeBudgetValue(value DownlinkNASTransportIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportIEContainerValueCodec) encodeChanged(value DownlinkNASTransportIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndicationIEContainer, error)
	encode  func(PWSFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndicationIEContainer, aper.DecodeState) (PWSFailureIndicationIEContainer, aper.Snapshot)
	compare func(PWSFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationIEContainerValueCodec) New(value PWSFailureIndicationIEContainer) (PWSFailureIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationIEContainerValueCodec) EncodeAPER(value PWSFailureIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationIEContainerValueCodec) encodeBudgetValue(value PWSFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationIEContainerValueCodec) encodeChanged(value PWSFailureIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequestIEContainer, error)
	encode  func(UEContextReleaseRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequestIEContainer, aper.DecodeState) (UEContextReleaseRequestIEContainer, aper.Snapshot)
	compare func(UEContextReleaseRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestIEContainerValueCodec) New(value UEContextReleaseRequestIEContainer) (UEContextReleaseRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestIEContainerValueCodec) EncodeAPER(value UEContextReleaseRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestIEContainerValueCodec) encodeBudgetValue(value UEContextReleaseRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestIEContainerValueCodec) encodeChanged(value UEContextReleaseRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, error)
	encode  func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) New(value DownlinkNASTransportIEValueProtocolErrorIEContainerList) (DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value DownlinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value DownlinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEValueProtocolErrorIEContainerList []DownlinkNASTransportIEValueProtocolIESingleContainer

func BridgeDownlinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *DownlinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(v *DownlinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value PWSFailureIndicationIEValueProtocolErrorIEContainerList) (PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PWSFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PWSFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEValueProtocolErrorIEContainerList []PWSFailureIndicationIEValueProtocolIESingleContainer

func BridgePWSFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *PWSFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *PWSFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextReleaseRequestIEValueProtocolErrorIEContainerList) (UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextReleaseRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEValueProtocolErrorIEContainerList []UEContextReleaseRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APProtocolErrorIEContainerList(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// DownlinkNASTransportIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, error)
	encode  func(DownlinkNASTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(DownlinkNASTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(DownlinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) New(value DownlinkNASTransportIEValueProtocolIEContainerList) (DownlinkNASTransportIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (DownlinkNASTransportIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return DownlinkNASTransportIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) EncodeAPER(value DownlinkNASTransportIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value DownlinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) encodeChanged(value DownlinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// DownlinkNASTransportIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEValueProtocolIEContainerList []DownlinkNASTransportIEValueProtocolIESingleContainer

func BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEContainerList(v *DownlinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEContainerList(v *DownlinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeDownlinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PWSFailureIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, error)
	encode  func(PWSFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PWSFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) New(value PWSFailureIndicationIEValueProtocolIEContainerList) (PWSFailureIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSFailureIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSFailureIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PWSFailureIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PWSFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value PWSFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSFailureIndicationIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEValueProtocolIEContainerList []PWSFailureIndicationIEValueProtocolIESingleContainer

func BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEContainerList(v *PWSFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSFailureIndicationIEValueCompareS1APProtocolIEContainerList(v *PWSFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, error)
	encode  func(UEContextReleaseRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) New(value UEContextReleaseRequestIEValueProtocolIEContainerList) (UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextReleaseRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEValueProtocolIEContainerList []UEContextReleaseRequestIEValueProtocolIESingleContainer

func BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEContainerList(v *UEContextReleaseRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEContainerList(v *UEContextReleaseRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// DownlinkNASTransportIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNASTransportIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEValueERABIEContainerListAPERValue) WithoutReplay() DownlinkNASTransportIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[DownlinkNASTransportIEValue].
type DownlinkNASTransportIEValueProtocolIESingleContainer = DownlinkNASTransportIEField

func BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(v *DownlinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeDownlinkNASTransportIEValueCompareS1APProtocolIESingleContainer(v *DownlinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PWSFailureIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSFailureIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() PWSFailureIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[PWSFailureIndicationIEValue].
type PWSFailureIndicationIEValueProtocolIESingleContainer = PWSFailureIndicationIEField

func BridgePWSFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(v *PWSFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePWSFailureIndicationIEValueCompareS1APProtocolIESingleContainer(v *PWSFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSFailureIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// UEContextReleaseRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextReleaseRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[UEContextReleaseRequestIEValue].
type UEContextReleaseRequestIEValueProtocolIESingleContainer = UEContextReleaseRequestIEField

func BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIESingleContainer(v *UEContextReleaseRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIESingleContainer(v *UEContextReleaseRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRestrictionListExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[HandoverRestrictionListExtIEsValue]].
type HandoverRestrictionListExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRestrictionListExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRestrictionListExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRestrictionListExtIEsExtFieldAPERValue) WithoutReplay() HandoverRestrictionListExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRestrictionListExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[HandoverRestrictionListExtIEsValue]].
type HandoverRestrictionListExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         HandoverRestrictionListExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRestrictionListExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRestrictionListExtIEsExtContainerAPERValue) WithoutReplay() HandoverRestrictionListExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportIEFieldAPERValue is the concrete APERValue[ProtocolIEField[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNASTransportIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEFieldAPERValue) WithoutReplay() DownlinkNASTransportIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationIEFieldAPERValue is the concrete APERValue[ProtocolIEField[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSFailureIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEFieldAPERValue) WithoutReplay() PWSFailureIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEFieldAPERValue) WithoutReplay() UEContextReleaseRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNASTransportIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEContainerAPERValue) WithoutReplay() DownlinkNASTransportIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSFailureIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEContainerAPERValue) WithoutReplay() PWSFailureIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEContainerAPERValue) WithoutReplay() UEContextReleaseRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNASTransportIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSFailureIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// DownlinkNASTransportIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[DownlinkNASTransportIEValue]].
type DownlinkNASTransportIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         DownlinkNASTransportIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) WithoutReplay() DownlinkNASTransportIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSFailureIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[PWSFailureIndicationIEValue]].
type PWSFailureIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSFailureIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() PWSFailureIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[UEContextReleaseRequestIEValue]].
type UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APDownlinkNASTransport(v *DownlinkNASTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APDownlinkNASTransport(v *DownlinkNASTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeDownlinkNASTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APDownlinkNASTransportIEValue(v *DownlinkNASTransportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s00.BridgeCaptureS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					BridgeCaptureS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
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
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
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
		case s00.ProtocolIEID(249):
			{
				f := s.Begin()
				s.Bool(v.rowDLNASPDUDeliveryAckRequest == nil)
				if v.rowDLNASPDUDeliveryAckRequest != nil {
					s00.BridgeCaptureS1APDLNASPDUDeliveryAckRequest(v.rowDLNASPDUDeliveryAckRequest, s)
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
		case s00.ProtocolIEID(275):
			{
				f := s.Begin()
				s.Bool(v.rowUECapabilityInfoRequest == nil)
				if v.rowUECapabilityInfoRequest != nil {
					s00.BridgeCaptureS1APUECapabilityInfoRequest(v.rowUECapabilityInfoRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(280):
			{
				f := s.Begin()
				s.Bool(v.rowEndIndication == nil)
				if v.rowEndIndication != nil {
					s00.BridgeCaptureS1APEndIndication(v.rowEndIndication, s)
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
					s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
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
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s00.BridgeCaptureS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkNASTransportIEValue) captureSemantics(s aper.SemanticCapture) DownlinkNASTransportIEValue {
	BridgeCaptureS1APDownlinkNASTransportIEValue(&v, &s)
	return v
}
func BridgeCompareS1APDownlinkNASTransportIEValue(v *DownlinkNASTransportIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(26):
			{
				f := s.Begin()
				s.Bool(v.rowNASPDU == nil)
				if v.rowNASPDU != nil {
					s02.BridgeCompareS1APNASPDU(v.rowNASPDU, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					BridgeCompareS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
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
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s06.BridgeCompareS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
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
		case s00.ProtocolIEID(249):
			{
				f := s.Begin()
				s.Bool(v.rowDLNASPDUDeliveryAckRequest == nil)
				if v.rowDLNASPDUDeliveryAckRequest != nil {
					s02.BridgeCompareS1APDLNASPDUDeliveryAckRequest(v.rowDLNASPDUDeliveryAckRequest, s)
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
		case s00.ProtocolIEID(275):
			{
				f := s.Begin()
				s.Bool(v.rowUECapabilityInfoRequest == nil)
				if v.rowUECapabilityInfoRequest != nil {
					s07.BridgeCompareS1APUECapabilityInfoRequest(v.rowUECapabilityInfoRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(280):
			{
				f := s.Begin()
				s.Bool(v.rowEndIndication == nil)
				if v.rowEndIndication != nil {
					s02.BridgeCompareS1APEndIndication(v.rowEndIndication, s)
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
					s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
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
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
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
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s02.BridgeCompareS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v DownlinkNASTransportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APDownlinkNASTransportIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APHandoverRestrictionList(v *HandoverRestrictionList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNidentity(&v.ServingPLMN, s)
	s.Bool(v.EquivalentPLMNs == nil)
	s00.BridgeCaptureS1APEPLMNs(&v.EquivalentPLMNs, s)
	s.Bool(v.ForbiddenTAs == nil)
	s21.BridgeCaptureS1APForbiddenTAs(&v.ForbiddenTAs, s)
	s.Bool(v.ForbiddenLAs == nil)
	s21.BridgeCaptureS1APForbiddenLAs(&v.ForbiddenLAs, s)
	{
		f := s.Begin()
		s.Bool(v.ForbiddenInterRATs == nil)
		if v.ForbiddenInterRATs != nil {
			s00.BridgeCaptureS1APForbiddenInterRATs(v.ForbiddenInterRATs, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeHandoverRestrictionListExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverRestrictionList(v *HandoverRestrictionList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNidentity(&v.ServingPLMN, s)
	s.Bool(v.EquivalentPLMNs == nil)
	s07.BridgeCompareS1APEPLMNs(&v.EquivalentPLMNs, s)
	s.Bool(v.ForbiddenTAs == nil)
	s24.BridgeCompareS1APForbiddenTAs(&v.ForbiddenTAs, s)
	s.Bool(v.ForbiddenLAs == nil)
	s24.BridgeCompareS1APForbiddenLAs(&v.ForbiddenLAs, s)
	{
		f := s.Begin()
		s.Bool(v.ForbiddenInterRATs == nil)
		if v.ForbiddenInterRATs != nil {
			s02.BridgeCompareS1APForbiddenInterRATs(v.ForbiddenInterRATs, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeHandoverRestrictionListExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APHandoverRestrictionListExtIEsValue(v *HandoverRestrictionListExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(261):
			{
				f := s.Begin()
				s.Bool(v.rowNRrestrictioninEPSasSecondaryRAT == nil)
				if v.rowNRrestrictioninEPSasSecondaryRAT != nil {
					s00.BridgeCaptureS1APNRrestrictioninEPSasSecondaryRAT(v.rowNRrestrictioninEPSasSecondaryRAT, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(270):
			{
				f := s.Begin()
				s.Bool(v.rowUnlicensedSpectrumRestriction == nil)
				if v.rowUnlicensedSpectrumRestriction != nil {
					s00.BridgeCaptureS1APUnlicensedSpectrumRestriction(v.rowUnlicensedSpectrumRestriction, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(282):
			{
				f := s.Begin()
				s.Bool(v.rowCNTypeRestrictions == nil)
				if v.rowCNTypeRestrictions != nil {
					s21.BridgeCaptureS1APCNTypeRestrictions(v.rowCNTypeRestrictions, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(287):
			{
				f := s.Begin()
				s.Bool(v.rowNRrestrictionin5GS == nil)
				if v.rowNRrestrictionin5GS != nil {
					s00.BridgeCaptureS1APNRrestrictionin5GS(v.rowNRrestrictionin5GS, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(290):
			{
				f := s.Begin()
				s.Bool(v.rowLastNGRANPLMNIdentity == nil)
				if v.rowLastNGRANPLMNIdentity != nil {
					s00.BridgeCaptureS1APPLMNidentity(v.rowLastNGRANPLMNIdentity, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(336):
			{
				f := s.Begin()
				s.Bool(v.rowRATRestrictions == nil)
				if v.rowRATRestrictions != nil {
					s21.BridgeCaptureS1APRATRestrictions(v.rowRATRestrictions, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRestrictionListExtIEsValue) captureSemantics(s aper.SemanticCapture) HandoverRestrictionListExtIEsValue {
	BridgeCaptureS1APHandoverRestrictionListExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APHandoverRestrictionListExtIEsValue(v *HandoverRestrictionListExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(261):
			{
				f := s.Begin()
				s.Bool(v.rowNRrestrictioninEPSasSecondaryRAT == nil)
				if v.rowNRrestrictioninEPSasSecondaryRAT != nil {
					s02.BridgeCompareS1APNRrestrictioninEPSasSecondaryRAT(v.rowNRrestrictioninEPSasSecondaryRAT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(270):
			{
				f := s.Begin()
				s.Bool(v.rowUnlicensedSpectrumRestriction == nil)
				if v.rowUnlicensedSpectrumRestriction != nil {
					s07.BridgeCompareS1APUnlicensedSpectrumRestriction(v.rowUnlicensedSpectrumRestriction, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(282):
			{
				f := s.Begin()
				s.Bool(v.rowCNTypeRestrictions == nil)
				if v.rowCNTypeRestrictions != nil {
					s21.BridgeCompareS1APCNTypeRestrictions(v.rowCNTypeRestrictions, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(287):
			{
				f := s.Begin()
				s.Bool(v.rowNRrestrictionin5GS == nil)
				if v.rowNRrestrictionin5GS != nil {
					s02.BridgeCompareS1APNRrestrictionin5GS(v.rowNRrestrictionin5GS, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(290):
			{
				f := s.Begin()
				s.Bool(v.rowLastNGRANPLMNIdentity == nil)
				if v.rowLastNGRANPLMNIdentity != nil {
					s07.BridgeCompareS1APPLMNidentity(v.rowLastNGRANPLMNIdentity, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(336):
			{
				f := s.Begin()
				s.Bool(v.rowRATRestrictions == nil)
				if v.rowRATRestrictions != nil {
					s24.BridgeCompareS1APRATRestrictions(v.rowRATRestrictions, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v HandoverRestrictionListExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APHandoverRestrictionListExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APNotificationCellListComplete(v *NotificationCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APNotificationCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APNotificationCellListComplete(v *NotificationCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APNotificationCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPC5QoSFlowListComplete(v *PC5QoSFlowListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APPC5QoSFlowList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPC5QoSFlowListComplete(v *PC5QoSFlowListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APPC5QoSFlowList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPLMNListforQMCComplete(v *PLMNListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPLMNListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPLMNListforQMCComplete(v *PLMNListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APPLMNListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPWSFailureIndication(v *PWSFailureIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPWSFailureIndication(v *PWSFailureIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSFailureIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPWSFailureIndicationIEValue(v *PWSFailureIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(222):
			{
				f := s.Begin()
				s.Bool(v.rowPWSfailedECGIList == nil)
				if v.rowPWSfailedECGIList != nil {
					s21.BridgeCaptureS1APPWSfailedECGIList(v.rowPWSfailedECGIList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCaptureS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PWSFailureIndicationIEValue) captureSemantics(s aper.SemanticCapture) PWSFailureIndicationIEValue {
	BridgeCaptureS1APPWSFailureIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPWSFailureIndicationIEValue(v *PWSFailureIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(222):
			{
				f := s.Begin()
				s.Bool(v.rowPWSfailedECGIList == nil)
				if v.rowPWSfailedECGIList != nil {
					s24.BridgeCompareS1APPWSfailedECGIList(v.rowPWSfailedECGIList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(59):
			{
				f := s.Begin()
				s.Bool(v.rowGlobalENBID == nil)
				if v.rowGlobalENBID != nil {
					s18.BridgeCompareS1APGlobalENBID(v.rowGlobalENBID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PWSFailureIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPWSFailureIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APPWSfailedECGIListComplete(v *PWSfailedECGIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APPWSfailedECGIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPWSfailedECGIListComplete(v *PWSfailedECGIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APPWSfailedECGIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRATRestrictionsComplete(v *RATRestrictionsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APRATRestrictions(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRATRestrictionsComplete(v *RATRestrictionsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APRATRestrictions(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRecommendedCellListComplete(v *RecommendedCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCaptureS1APRecommendedCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedCellListComplete(v *RecommendedCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCompareS1APRecommendedCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRecommendedENBListComplete(v *RecommendedENBListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s33.BridgeCaptureS1APRecommendedENBList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedENBListComplete(v *RecommendedENBListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s33.BridgeCompareS1APRecommendedENBList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APReportingCellListComplete(v *ReportingCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APReportingCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APReportingCellListComplete(v *ReportingCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APReportingCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APRequestedCellListComplete(v *RequestedCellListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s21.BridgeCaptureS1APRequestedCellList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRequestedCellListComplete(v *RequestedCellListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s24.BridgeCompareS1APRequestedCellList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSecondaryRATDataUsageReportListComplete(v *SecondaryRATDataUsageReportListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSecondaryRATDataUsageReportListComplete(v *SecondaryRATDataUsageReportListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSensorMeasConfigNameListComplete(v *SensorMeasConfigNameListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APSensorMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSensorMeasConfigNameListComplete(v *SensorMeasConfigNameListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APSensorMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APServedDCNsComplete(v *ServedDCNsComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCaptureS1APServedDCNs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APServedDCNsComplete(v *ServedDCNsComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s30.BridgeCompareS1APServedDCNs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextReleaseRequest(v *UEContextReleaseRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseRequest(v *UEContextReleaseRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextReleaseRequestIEValue(v *UEContextReleaseRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(164):
			{
				f := s.Begin()
				s.Bool(v.rowGWContextReleaseIndication == nil)
				if v.rowGWContextReleaseIndication != nil {
					s00.BridgeCaptureS1APGWContextReleaseIndication(v.rowGWContextReleaseIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseRequestIEValue) captureSemantics(s aper.SemanticCapture) UEContextReleaseRequestIEValue {
	BridgeCaptureS1APUEContextReleaseRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextReleaseRequestIEValue(v *UEContextReleaseRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(164):
			{
				f := s.Begin()
				s.Bool(v.rowGWContextReleaseIndication == nil)
				if v.rowGWContextReleaseIndication != nil {
					s02.BridgeCompareS1APGWContextReleaseIndication(v.rowGWContextReleaseIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(264):
			{
				f := s.Begin()
				s.Bool(v.rowSecondaryRATDataUsageReportList == nil)
				if v.rowSecondaryRATDataUsageReportList != nil {
					s28.BridgeCompareS1APSecondaryRATDataUsageReportList(v.rowSecondaryRATDataUsageReportList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextReleaseRequestIEValue(&v, &s)
	return s
}

// HandoverRestrictionList represents the ASN.1 type HandoverRestrictionList (SEQUENCE).
type HandoverRestrictionList struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	received             bool
	withoutReplay        bool
	receivedAbsolute     bool
	receivedBytes        aper.WireSpan
	receivedLocation     aper.Location
	ServingPLMN          s00.PLMNidentity                          `asn1:"tag:0,context,implicit"`
	EquivalentPLMNs      s00.EPLMNs                                `asn1:"tag:1,context,implicit,optional" json:"EquivalentPLMNs,omitzero"`
	equivalentPLMNsIndef bool                                      `asn1:"-" json:"-"`
	ForbiddenTAs         s18.ForbiddenTAs                          `asn1:"tag:2,context,implicit,optional" json:"ForbiddenTAs,omitzero"`
	forbiddenTAsIndef    bool                                      `asn1:"-" json:"-"`
	ForbiddenLAs         s18.ForbiddenLAs                          `asn1:"tag:3,context,implicit,optional" json:"ForbiddenLAs,omitzero"`
	forbiddenLAsIndef    bool                                      `asn1:"-" json:"-"`
	ForbiddenInterRATs   *s00.ForbiddenInterRATs                   `asn1:"tag:4,context,implicit,optional" json:"ForbiddenInterRATs,omitempty"`
	IEExtensions         HandoverRestrictionListExtIEsExtContainer `asn1:"tag:5,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                      `asn1:"-" json:"-"`
	extCount             int64                                     `asn1:"-" json:"-"`
	extPresent           []bool                                    `asn1:"-" json:"-"`
	extData              [][]byte                                  `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// ServedDCNsComplete carries a complete ServedDCNs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ServedDCNsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s30.ServedDCNs
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ServedDCNsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERServedDCNsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ServedDCNs from APER format.
func (v *ServedDCNsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ServedDCNs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ServedDCNsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNs")
	}
	value, err := BridgeUnmarshalAPERServedDCNsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNs")
	}
	padding, err := aper.CaptureFinalBits(bb, "ServedDCNs")
	if err != nil {
		return runtime.WrapDecodePath(err, "ServedDCNs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERServedDCNs encodes a ServedDCNs list to APER.
func BridgeMarshalAPERServedDCNs(list ServedDCNsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERServedDCNs decodes a ServedDCNs list from APER.
func BridgeUnmarshalAPERServedDCNs(data []byte) (ServedDCNsComplete, error) {
	var value ServedDCNsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERServedDCNsFrom decodes a ServedDCNs list from bb.
func BridgeUnmarshalAPERServedDCNsFrom(bb *aper.BitBuffer) (s30.ServedDCNs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s30.BridgeAsn1cAPERServedDCNsListValue
	if err := BridgeUnmarshalAPERServedDCNsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERServedDCNsInto(v *s30.BridgeAsn1cAPERServedDCNsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s30.ServedDCNs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s30.ServedDCNsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s30.BridgeServedDCNsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// PWSfailedECGIListComplete carries a complete PWSfailedECGIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PWSfailedECGIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.PWSfailedECGIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *PWSfailedECGIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERPWSfailedECGIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PWSfailedECGIList from APER format.
func (v *PWSfailedECGIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PWSfailedECGIList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PWSfailedECGIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PWSfailedECGIList")
	}
	value, err := BridgeUnmarshalAPERPWSfailedECGIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PWSfailedECGIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "PWSfailedECGIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "PWSfailedECGIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPWSfailedECGIList encodes a PWSfailedECGIList list to APER.
func BridgeMarshalAPERPWSfailedECGIList(list PWSfailedECGIListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERPWSfailedECGIList decodes a PWSfailedECGIList list from APER.
func BridgeUnmarshalAPERPWSfailedECGIList(data []byte) (PWSfailedECGIListComplete, error) {
	var value PWSfailedECGIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPWSfailedECGIListFrom decodes a PWSfailedECGIList list from bb.
func BridgeUnmarshalAPERPWSfailedECGIListFrom(bb *aper.BitBuffer) (s20.PWSfailedECGIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERPWSfailedECGIListListValue
	if err := BridgeUnmarshalAPERPWSfailedECGIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPWSfailedECGIListInto(v *s21.BridgeAsn1cAPERPWSfailedECGIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.PWSfailedECGIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes HandoverRestrictionList to APER format.
func (v *HandoverRestrictionList) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverRestrictionList) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.EquivalentPLMNs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ForbiddenTAs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ForbiddenLAs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.ForbiddenInterRATs != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.ServingPLMN), 3, 3, true); err != nil {
		return fmt.Errorf("encoding servingPLMN: %w", err)
	}
	if v.EquivalentPLMNs != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.EquivalentPLMNs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, true, func(fragmentOffset_equivalentplmns, fragmentLength_equivalentplmns int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_equivalentplmns < 0 || fragmentOffset_equivalentplmns > int64(len(v.EquivalentPLMNs)) || fragmentLength_equivalentplmns < 0 || fragmentLength_equivalentplmns > int64(len(v.EquivalentPLMNs[fragmentOffset_equivalentplmns:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.EquivalentPLMNs[fragmentOffset_equivalentplmns : fragmentOffset_equivalentplmns+fragmentLength_equivalentplmns] {
				if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 3, 3, true); err != nil {
					return fmt.Errorf("encoding equivalentPLMNs element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding equivalentPLMNs: %w", err)
		}
	}
	if v.ForbiddenTAs != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.ForbiddenTAs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_forbiddentas, fragmentLength_forbiddentas int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_forbiddentas < 0 || fragmentOffset_forbiddentas > int64(len(v.ForbiddenTAs)) || fragmentLength_forbiddentas < 0 || fragmentLength_forbiddentas > int64(len(v.ForbiddenTAs[fragmentOffset_forbiddentas:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ForbiddenTAs[fragmentOffset_forbiddentas : fragmentOffset_forbiddentas+fragmentLength_forbiddentas] {
				if err := s18.BridgeForbiddenTAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding forbiddenTAs element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding forbiddenTAs: %w", err)
		}
	}
	if v.ForbiddenLAs != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.ForbiddenLAs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_forbiddenlas, fragmentLength_forbiddenlas int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_forbiddenlas < 0 || fragmentOffset_forbiddenlas > int64(len(v.ForbiddenLAs)) || fragmentLength_forbiddenlas < 0 || fragmentLength_forbiddenlas > int64(len(v.ForbiddenLAs[fragmentOffset_forbiddenlas:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ForbiddenLAs[fragmentOffset_forbiddenlas : fragmentOffset_forbiddenlas+fragmentLength_forbiddenlas] {
				if err := s18.BridgeForbiddenLAsItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding forbiddenLAs element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding forbiddenLAs: %w", err)
		}
	}
	if v.ForbiddenInterRATs != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.ForbiddenInterRATs), 4, true); err != nil {
			return fmt.Errorf("encoding forbiddenInterRATs: %w", err)
		}
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

// UnmarshalAPER decodes HandoverRestrictionList from APER format.
func (v *HandoverRestrictionList) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverRestrictionList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverRestrictionList) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRestrictionList")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRestrictionList")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRestrictionList")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRestrictionList")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverRestrictionList) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRestrictionList{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_equivalentplmns, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_forbiddentas, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_forbiddenlas, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_forbiddeninterrats, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_servingplmn, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServingPLMN")
	}
	v.ServingPLMN = s00.PLMNidentity(val_servingplmn)
	if opt_equivalentplmns {
		tmp_equivalentplmns := make(s00.EPLMNs, 0)
		_, errCollection_equivalentplmns := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 15, HasUpper: true}, true, func(fragmentOffset_equivalentplmns, fragmentLength_equivalentplmns int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
			if fragmentOffset_equivalentplmns < 0 || fragmentLength_equivalentplmns < 0 || fragmentLength_equivalentplmns > int64(^uint(0)>>1) || fragmentOffset_equivalentplmns > int64(^uint(0)>>1)-fragmentLength_equivalentplmns {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_equivalentplmns; i++ {
				val, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("EquivalentPLMNs[%d]", fragmentOffset_equivalentplmns+i))
				}
				if next, err := aper.AppendValues(bb, tmp_equivalentplmns, val); err != nil {
					return err
				} else {
					tmp_equivalentplmns = next
				}
			}
			return nil
		})
		if errCollection_equivalentplmns != nil {
			return runtime.WrapDecodePath(errCollection_equivalentplmns, "EquivalentPLMNs")
		}
		v.EquivalentPLMNs = tmp_equivalentplmns
	}
	if opt_forbiddentas {
		toleranceMark_forbiddentas := bb.EnterComponent("ForbiddenTAs")
		tmp_forbiddentas := make(s18.ForbiddenTAs, 0)
		_, errCollection_forbiddentas := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_forbiddentas, fragmentLength_forbiddentas int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_forbiddentas < 0 || fragmentLength_forbiddentas < 0 || fragmentLength_forbiddentas > int64(^uint(0)>>1) || fragmentOffset_forbiddentas > int64(^uint(0)>>1)-fragmentLength_forbiddentas {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_forbiddentas; i++ {
				var elem s18.ForbiddenTAsItem
				elementMark := bb.EnterIndex(fragmentOffset_forbiddentas + i)
				if err := s18.BridgeForbiddenTAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenTAs[%d]", fragmentOffset_forbiddentas+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_forbiddentas, elem); err != nil {
					return err
				} else {
					tmp_forbiddentas = next
				}
			}
			return nil
		})
		if errCollection_forbiddentas != nil {
			return runtime.WrapDecodePath(errCollection_forbiddentas, "ForbiddenTAs")
		}
		v.ForbiddenTAs = tmp_forbiddentas
		bb.LeaveComponent(toleranceMark_forbiddentas)
	}
	if opt_forbiddenlas {
		toleranceMark_forbiddenlas := bb.EnterComponent("ForbiddenLAs")
		tmp_forbiddenlas := make(s18.ForbiddenLAs, 0)
		_, errCollection_forbiddenlas := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_forbiddenlas, fragmentLength_forbiddenlas int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_forbiddenlas < 0 || fragmentLength_forbiddenlas < 0 || fragmentLength_forbiddenlas > int64(^uint(0)>>1) || fragmentOffset_forbiddenlas > int64(^uint(0)>>1)-fragmentLength_forbiddenlas {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_forbiddenlas; i++ {
				var elem s18.ForbiddenLAsItem
				elementMark := bb.EnterIndex(fragmentOffset_forbiddenlas + i)
				if err := s18.BridgeForbiddenLAsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ForbiddenLAs[%d]", fragmentOffset_forbiddenlas+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_forbiddenlas, elem); err != nil {
					return err
				} else {
					tmp_forbiddenlas = next
				}
			}
			return nil
		})
		if errCollection_forbiddenlas != nil {
			return runtime.WrapDecodePath(errCollection_forbiddenlas, "ForbiddenLAs")
		}
		v.ForbiddenLAs = tmp_forbiddenlas
		bb.LeaveComponent(toleranceMark_forbiddenlas)
	}
	if opt_forbiddeninterrats {
		val_forbiddeninterrats, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 2, Path: "ForbiddenInterRATs"})
		if err != nil {
			return runtime.WrapDecodePath(err, "ForbiddenInterRATs")
		}
		tmp_forbiddeninterrats := s00.ForbiddenInterRATs(val_forbiddeninterrats)
		if err := aper.ChargeValue(bb, tmp_forbiddeninterrats); err != nil {
			return err
		}
		v.ForbiddenInterRATs = (*s00.ForbiddenInterRATs)(bb.OwnInt64(int64(tmp_forbiddeninterrats)))

	}
	if opt_ieextensions {
		tmp_ieextensions := make(HandoverRestrictionListExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem HandoverRestrictionListExtIEsExtField
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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

// PC5QoSFlowListComplete carries a complete PC5QoSFlowList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PC5QoSFlowListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.PC5QoSFlowList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *PC5QoSFlowListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERPC5QoSFlowListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PC5QoSFlowList from APER format.
func (v *PC5QoSFlowListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PC5QoSFlowList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PC5QoSFlowListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowList")
	}
	value, err := BridgeUnmarshalAPERPC5QoSFlowListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowList")
	}
	padding, err := aper.CaptureFinalBits(bb, "PC5QoSFlowList")
	if err != nil {
		return runtime.WrapDecodePath(err, "PC5QoSFlowList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPC5QoSFlowList encodes a PC5QoSFlowList list to APER.
func BridgeMarshalAPERPC5QoSFlowList(list PC5QoSFlowListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERPC5QoSFlowList decodes a PC5QoSFlowList list from APER.
func BridgeUnmarshalAPERPC5QoSFlowList(data []byte) (PC5QoSFlowListComplete, error) {
	var value PC5QoSFlowListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPC5QoSFlowListFrom decodes a PC5QoSFlowList list from bb.
func BridgeUnmarshalAPERPC5QoSFlowListFrom(bb *aper.BitBuffer) (s20.PC5QoSFlowList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERPC5QoSFlowListListValue
	if err := BridgeUnmarshalAPERPC5QoSFlowListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPC5QoSFlowListInto(v *s21.BridgeAsn1cAPERPC5QoSFlowListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.PC5QoSFlowList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.PC5QoSFlowItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgePC5QoSFlowItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// PLMNListforQMCComplete carries a complete PLMNListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PLMNListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.PLMNListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *PLMNListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERPLMNListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PLMNListforQMC from APER format.
func (v *PLMNListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PLMNListforQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PLMNListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PLMNListforQMC")
	}
	value, err := BridgeUnmarshalAPERPLMNListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "PLMNListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPLMNListforQMC encodes a PLMNListforQMC list to APER.
func BridgeMarshalAPERPLMNListforQMC(list PLMNListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERPLMNListforQMC decodes a PLMNListforQMC list from APER.
func BridgeUnmarshalAPERPLMNListforQMC(data []byte) (PLMNListforQMCComplete, error) {
	var value PLMNListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPLMNListforQMCFrom decodes a PLMNListforQMC list from bb.
func BridgeUnmarshalAPERPLMNListforQMCFrom(bb *aper.BitBuffer) (s00.PLMNListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERPLMNListforQMCListValue
	if err := BridgeUnmarshalAPERPLMNListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPLMNListforQMCInto(v *s00.BridgeAsn1cAPERPLMNListforQMCListValue, bb *aper.BitBuffer) error {
	v.Value = make(s00.PLMNListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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
	return nil
}

// RecommendedCellListComplete carries a complete RecommendedCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type RecommendedCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s26.RecommendedCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *RecommendedCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s26.BridgeMarshalAPERRecommendedCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes RecommendedCellList from APER format.
func (v *RecommendedCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellList")
	}
	value, err := BridgeUnmarshalAPERRecommendedCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERRecommendedCellList encodes a RecommendedCellList list to APER.
func BridgeMarshalAPERRecommendedCellList(list RecommendedCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERRecommendedCellList decodes a RecommendedCellList list from APER.
func BridgeUnmarshalAPERRecommendedCellList(data []byte) (RecommendedCellListComplete, error) {
	var value RecommendedCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERRecommendedCellListFrom decodes a RecommendedCellList list from bb.
func BridgeUnmarshalAPERRecommendedCellListFrom(bb *aper.BitBuffer) (s26.RecommendedCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s26.BridgeAsn1cAPERRecommendedCellListListValue
	if err := BridgeUnmarshalAPERRecommendedCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERRecommendedCellListInto(v *s26.BridgeAsn1cAPERRecommendedCellListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s26.RecommendedCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s26.RecommendedCellItemIEValueProtocolIESingleContainer
			if err := s26.BridgeRecommendedCellItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
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
	return nil
}

// RecommendedENBListComplete carries a complete RecommendedENBList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type RecommendedENBListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.RecommendedENBList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *RecommendedENBListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERRecommendedENBListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes RecommendedENBList from APER format.
func (v *RecommendedENBListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedENBList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedENBListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBList")
	}
	value, err := BridgeUnmarshalAPERRecommendedENBListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBList")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedENBList")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERRecommendedENBList encodes a RecommendedENBList list to APER.
func BridgeMarshalAPERRecommendedENBList(list RecommendedENBListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERRecommendedENBList decodes a RecommendedENBList list from APER.
func BridgeUnmarshalAPERRecommendedENBList(data []byte) (RecommendedENBListComplete, error) {
	var value RecommendedENBListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERRecommendedENBListFrom decodes a RecommendedENBList list from bb.
func BridgeUnmarshalAPERRecommendedENBListFrom(bb *aper.BitBuffer) (s32.RecommendedENBList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERRecommendedENBListListValue
	if err := BridgeUnmarshalAPERRecommendedENBListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERRecommendedENBListInto(v *s32.BridgeAsn1cAPERRecommendedENBListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s32.RecommendedENBList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s32.RecommendedENBItemIEValueProtocolIESingleContainer
			if err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
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
	return nil
}

// RATRestrictionsComplete carries a complete RATRestrictions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type RATRestrictionsComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.RATRestrictions
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *RATRestrictionsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERRATRestrictionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes RATRestrictions from APER format.
func (v *RATRestrictionsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RATRestrictions with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RATRestrictionsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictions")
	}
	value, err := BridgeUnmarshalAPERRATRestrictionsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictions")
	}
	padding, err := aper.CaptureFinalBits(bb, "RATRestrictions")
	if err != nil {
		return runtime.WrapDecodePath(err, "RATRestrictions")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERRATRestrictions encodes a RATRestrictions list to APER.
func BridgeMarshalAPERRATRestrictions(list RATRestrictionsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERRATRestrictions decodes a RATRestrictions list from APER.
func BridgeUnmarshalAPERRATRestrictions(data []byte) (RATRestrictionsComplete, error) {
	var value RATRestrictionsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERRATRestrictionsFrom decodes a RATRestrictions list from bb.
func BridgeUnmarshalAPERRATRestrictionsFrom(bb *aper.BitBuffer) (s20.RATRestrictions, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERRATRestrictionsListValue
	if err := BridgeUnmarshalAPERRATRestrictionsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERRATRestrictionsInto(v *s21.BridgeAsn1cAPERRATRestrictionsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.RATRestrictions, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.RATRestrictionsItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeRATRestrictionsItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// SecondaryRATDataUsageReportListComplete carries a complete SecondaryRATDataUsageReportList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SecondaryRATDataUsageReportListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s28.SecondaryRATDataUsageReportList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *SecondaryRATDataUsageReportListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s28.BridgeMarshalAPERSecondaryRATDataUsageReportListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SecondaryRATDataUsageReportList from APER format.
func (v *SecondaryRATDataUsageReportListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SecondaryRATDataUsageReportList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SecondaryRATDataUsageReportListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
	}
	value, err := BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
	}
	padding, err := aper.CaptureFinalBits(bb, "SecondaryRATDataUsageReportList")
	if err != nil {
		return runtime.WrapDecodePath(err, "SecondaryRATDataUsageReportList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSecondaryRATDataUsageReportList encodes a SecondaryRATDataUsageReportList list to APER.
func BridgeMarshalAPERSecondaryRATDataUsageReportList(list SecondaryRATDataUsageReportListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSecondaryRATDataUsageReportList decodes a SecondaryRATDataUsageReportList list from APER.
func BridgeUnmarshalAPERSecondaryRATDataUsageReportList(data []byte) (SecondaryRATDataUsageReportListComplete, error) {
	var value SecondaryRATDataUsageReportListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSecondaryRATDataUsageReportListFrom decodes a SecondaryRATDataUsageReportList list from bb.
func BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(bb *aper.BitBuffer) (s28.SecondaryRATDataUsageReportList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s28.BridgeAsn1cAPERSecondaryRATDataUsageReportListListValue
	if err := BridgeUnmarshalAPERSecondaryRATDataUsageReportListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSecondaryRATDataUsageReportListInto(v *s28.BridgeAsn1cAPERSecondaryRATDataUsageReportListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s28.SecondaryRATDataUsageReportList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s28.SecondaryRATDataUsageReportItemIEValueProtocolIESingleContainer
			if err := s28.BridgeSecondaryRATDataUsageReportItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
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
	return nil
}

// SensorMeasConfigNameListComplete carries a complete SensorMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SensorMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s30.SensorMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *SensorMeasConfigNameListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s30.BridgeMarshalAPERSensorMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SensorMeasConfigNameList from APER format.
func (v *SensorMeasConfigNameListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SensorMeasConfigNameList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SensorMeasConfigNameListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameList")
	}
	value, err := BridgeUnmarshalAPERSensorMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "SensorMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "SensorMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSensorMeasConfigNameList encodes a SensorMeasConfigNameList list to APER.
func BridgeMarshalAPERSensorMeasConfigNameList(list SensorMeasConfigNameListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSensorMeasConfigNameList decodes a SensorMeasConfigNameList list from APER.
func BridgeUnmarshalAPERSensorMeasConfigNameList(data []byte) (SensorMeasConfigNameListComplete, error) {
	var value SensorMeasConfigNameListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSensorMeasConfigNameListFrom decodes a SensorMeasConfigNameList list from bb.
func BridgeUnmarshalAPERSensorMeasConfigNameListFrom(bb *aper.BitBuffer) (s30.SensorMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s30.BridgeAsn1cAPERSensorMeasConfigNameListListValue
	if err := BridgeUnmarshalAPERSensorMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSensorMeasConfigNameListInto(v *s30.BridgeAsn1cAPERSensorMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s30.SensorMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s30.SensorMeasConfigNameItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s30.BridgeSensorMeasConfigNameItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *HandoverRestrictionList) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverRestrictionList", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverRestrictionList", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverRestrictionList) WithoutReplay() HandoverRestrictionList {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverRestrictionList
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PC5QoSFlowListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PC5QoSFlowListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PC5QoSFlowListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PC5QoSFlowListComplete) WithoutReplay() PC5QoSFlowListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PC5QoSFlowListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PLMNListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PLMNListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PLMNListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PLMNListforQMCComplete) WithoutReplay() PLMNListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PLMNListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PWSfailedECGIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PWSfailedECGIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PWSfailedECGIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PWSfailedECGIListComplete) WithoutReplay() PWSfailedECGIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PWSfailedECGIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RATRestrictionsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RATRestrictionsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RATRestrictionsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RATRestrictionsComplete) WithoutReplay() RATRestrictionsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RATRestrictionsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RecommendedCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedCellListComplete) WithoutReplay() RecommendedCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RecommendedENBListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedENBListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedENBListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedENBListComplete) WithoutReplay() RecommendedENBListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedENBListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SecondaryRATDataUsageReportListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SecondaryRATDataUsageReportListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SecondaryRATDataUsageReportListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SecondaryRATDataUsageReportListComplete) WithoutReplay() SecondaryRATDataUsageReportListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SecondaryRATDataUsageReportListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SensorMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SensorMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SensorMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SensorMeasConfigNameListComplete) WithoutReplay() SensorMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SensorMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ServedDCNsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ServedDCNsComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ServedDCNsComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ServedDCNsComplete) WithoutReplay() ServedDCNsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ServedDCNsComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverRestrictionList) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverRestrictionList) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRestrictionList.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRestrictionList.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverRestrictionList) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRestrictionList.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRestrictionList.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverRestrictionList) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverRestrictionList")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverRestrictionList) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverRestrictionList")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverRestrictionList(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverRestrictionList")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverRestrictionList")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverRestrictionList) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverRestrictionList")
}
func (v *HandoverRestrictionList) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverRestrictionList")
}
func (v *HandoverRestrictionList) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverRestrictionList(v, &s)
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
func (v *HandoverRestrictionList) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverRestrictionList) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PC5QoSFlowListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PC5QoSFlowListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PC5QoSFlowListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PC5QoSFlowListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPC5QoSFlowListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PC5QoSFlowListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PC5QoSFlowListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PC5QoSFlowListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PC5QoSFlowListComplete")
}
func (v *PC5QoSFlowListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PC5QoSFlowListComplete")
}
func (v *PC5QoSFlowListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPC5QoSFlowListComplete(v, &s)
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
func (v *PC5QoSFlowListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PC5QoSFlowListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERPC5QoSFlowListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PLMNListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PLMNListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PLMNListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PLMNListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPLMNListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PLMNListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PLMNListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PLMNListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PLMNListforQMCComplete")
}
func (v *PLMNListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PLMNListforQMCComplete")
}
func (v *PLMNListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPLMNListforQMCComplete(v, &s)
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
func (v *PLMNListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PLMNListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERPLMNListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PWSfailedECGIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PWSfailedECGIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PWSfailedECGIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PWSfailedECGIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPWSfailedECGIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PWSfailedECGIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PWSfailedECGIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PWSfailedECGIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PWSfailedECGIListComplete")
}
func (v *PWSfailedECGIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PWSfailedECGIListComplete")
}
func (v *PWSfailedECGIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPWSfailedECGIListComplete(v, &s)
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
func (v *PWSfailedECGIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PWSfailedECGIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERPWSfailedECGIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *RATRestrictionsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RATRestrictionsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RATRestrictionsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RATRestrictionsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRATRestrictionsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RATRestrictionsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RATRestrictionsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RATRestrictionsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RATRestrictionsComplete")
}
func (v *RATRestrictionsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RATRestrictionsComplete")
}
func (v *RATRestrictionsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRATRestrictionsComplete(v, &s)
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
func (v *RATRestrictionsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RATRestrictionsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERRATRestrictionsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *RecommendedCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedCellListComplete")
}
func (v *RecommendedCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedCellListComplete")
}
func (v *RecommendedCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedCellListComplete(v, &s)
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
func (v *RecommendedCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s26.BridgeMarshalAPERRecommendedCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *RecommendedENBListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedENBListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedENBListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedENBListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedENBListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedENBListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedENBListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedENBListComplete")
}
func (v *RecommendedENBListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedENBListComplete")
}
func (v *RecommendedENBListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedENBListComplete(v, &s)
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
func (v *RecommendedENBListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedENBListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERRecommendedENBListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SecondaryRATDataUsageReportListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SecondaryRATDataUsageReportListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReportListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSecondaryRATDataUsageReportListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SecondaryRATDataUsageReportListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SecondaryRATDataUsageReportListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReportListComplete")
}
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SecondaryRATDataUsageReportListComplete")
}
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSecondaryRATDataUsageReportListComplete(v, &s)
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
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SecondaryRATDataUsageReportListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s28.BridgeMarshalAPERSecondaryRATDataUsageReportListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SensorMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SensorMeasConfigNameListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SensorMeasConfigNameListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SensorMeasConfigNameListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSensorMeasConfigNameListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SensorMeasConfigNameListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SensorMeasConfigNameListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SensorMeasConfigNameListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SensorMeasConfigNameListComplete")
}
func (v *SensorMeasConfigNameListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SensorMeasConfigNameListComplete")
}
func (v *SensorMeasConfigNameListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSensorMeasConfigNameListComplete(v, &s)
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
func (v *SensorMeasConfigNameListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SensorMeasConfigNameListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERSensorMeasConfigNameListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ServedDCNsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ServedDCNsComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ServedDCNsComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ServedDCNsComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APServedDCNsComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ServedDCNsComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ServedDCNsComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ServedDCNsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ServedDCNsComplete")
}
func (v *ServedDCNsComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ServedDCNsComplete")
}
func (v *ServedDCNsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APServedDCNsComplete(v, &s)
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
func (v *ServedDCNsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ServedDCNsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s30.BridgeMarshalAPERServedDCNsTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverRestrictionList) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverRestrictionList")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverRestrictionList
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverRestrictionList(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverRestrictionList{}
		return report, aper.OperationError(err, "HandoverRestrictionList")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverRestrictionList")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PC5QoSFlowListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PC5QoSFlowListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PC5QoSFlowListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPC5QoSFlowListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PC5QoSFlowListComplete{}
		return report, aper.OperationError(err, "PC5QoSFlowListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PC5QoSFlowListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PLMNListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PLMNListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PLMNListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPLMNListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PLMNListforQMCComplete{}
		return report, aper.OperationError(err, "PLMNListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PLMNListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PWSfailedECGIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PWSfailedECGIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PWSfailedECGIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPWSfailedECGIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PWSfailedECGIListComplete{}
		return report, aper.OperationError(err, "PWSfailedECGIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PWSfailedECGIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RATRestrictionsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RATRestrictionsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RATRestrictionsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRATRestrictionsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RATRestrictionsComplete{}
		return report, aper.OperationError(err, "RATRestrictionsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RATRestrictionsComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RecommendedCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedCellListComplete{}
		return report, aper.OperationError(err, "RecommendedCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RecommendedENBListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedENBListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedENBListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedENBListComplete{}
		return report, aper.OperationError(err, "RecommendedENBListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedENBListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SecondaryRATDataUsageReportListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SecondaryRATDataUsageReportListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SecondaryRATDataUsageReportListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSecondaryRATDataUsageReportListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SecondaryRATDataUsageReportListComplete{}
		return report, aper.OperationError(err, "SecondaryRATDataUsageReportListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SecondaryRATDataUsageReportListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SensorMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SensorMeasConfigNameListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SensorMeasConfigNameListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSensorMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SensorMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "SensorMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SensorMeasConfigNameListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ServedDCNsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ServedDCNsComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ServedDCNsComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APServedDCNsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ServedDCNsComplete{}
		return report, aper.OperationError(err, "ServedDCNsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ServedDCNsComplete")
}

// MarshalAPERServedDCNs encodes a complete named list.
func MarshalAPERServedDCNs(v ServedDCNsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPWSfailedECGIList encodes a complete named list.
func MarshalAPERPWSfailedECGIList(v PWSfailedECGIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPC5QoSFlowList encodes a complete named list.
func MarshalAPERPC5QoSFlowList(v PC5QoSFlowListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPLMNListforQMC encodes a complete named list.
func MarshalAPERPLMNListforQMC(v PLMNListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERRecommendedCellList encodes a complete named list.
func MarshalAPERRecommendedCellList(v RecommendedCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERRecommendedENBList encodes a complete named list.
func MarshalAPERRecommendedENBList(v RecommendedENBListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERRATRestrictions encodes a complete named list.
func MarshalAPERRATRestrictions(v RATRestrictionsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSecondaryRATDataUsageReportList encodes a complete named list.
func MarshalAPERSecondaryRATDataUsageReportList(v SecondaryRATDataUsageReportListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSensorMeasConfigNameList encodes a complete named list.
func MarshalAPERSensorMeasConfigNameList(v SensorMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERServedDCNs decodes a complete named list.
func UnmarshalAPERServedDCNs(data []byte, options ...aper.DecodeOption) (ServedDCNsComplete, aper.DecodeReport, error) {
	var v ServedDCNsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPWSfailedECGIList decodes a complete named list.
func UnmarshalAPERPWSfailedECGIList(data []byte, options ...aper.DecodeOption) (PWSfailedECGIListComplete, aper.DecodeReport, error) {
	var v PWSfailedECGIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPC5QoSFlowList decodes a complete named list.
func UnmarshalAPERPC5QoSFlowList(data []byte, options ...aper.DecodeOption) (PC5QoSFlowListComplete, aper.DecodeReport, error) {
	var v PC5QoSFlowListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPLMNListforQMC decodes a complete named list.
func UnmarshalAPERPLMNListforQMC(data []byte, options ...aper.DecodeOption) (PLMNListforQMCComplete, aper.DecodeReport, error) {
	var v PLMNListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERRecommendedCellList decodes a complete named list.
func UnmarshalAPERRecommendedCellList(data []byte, options ...aper.DecodeOption) (RecommendedCellListComplete, aper.DecodeReport, error) {
	var v RecommendedCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERRecommendedENBList decodes a complete named list.
func UnmarshalAPERRecommendedENBList(data []byte, options ...aper.DecodeOption) (RecommendedENBListComplete, aper.DecodeReport, error) {
	var v RecommendedENBListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERRATRestrictions decodes a complete named list.
func UnmarshalAPERRATRestrictions(data []byte, options ...aper.DecodeOption) (RATRestrictionsComplete, aper.DecodeReport, error) {
	var v RATRestrictionsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSecondaryRATDataUsageReportList decodes a complete named list.
func UnmarshalAPERSecondaryRATDataUsageReportList(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageReportListComplete, aper.DecodeReport, error) {
	var v SecondaryRATDataUsageReportListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSensorMeasConfigNameList decodes a complete named list.
func UnmarshalAPERSensorMeasConfigNameList(data []byte, options ...aper.DecodeOption) (SensorMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v SensorMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UEContextReleaseRequest represents the ASN.1 type UEContextReleaseRequest (SEQUENCE).
type UEContextReleaseRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      UEContextReleaseRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// DownlinkNASTransport represents the ASN.1 type DownlinkNASTransport (SEQUENCE).
type DownlinkNASTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      DownlinkNASTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// PWSFailureIndication represents the ASN.1 type PWSFailureIndication (SEQUENCE).
type PWSFailureIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PWSFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UEContextReleaseRequest to APER format.
func (v *UEContextReleaseRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes UEContextReleaseRequest from APER format.
func (v *UEContextReleaseRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextReleaseRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextReleaseRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextReleaseRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(UEContextReleaseRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem UEContextReleaseRequestIEField
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

// MarshalAPER encodes DownlinkNASTransport to APER format.
func (v *DownlinkNASTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *DownlinkNASTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes DownlinkNASTransport from APER format.
func (v *DownlinkNASTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes DownlinkNASTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *DownlinkNASTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNASTransport")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNASTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "DownlinkNASTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "DownlinkNASTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *DownlinkNASTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = DownlinkNASTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(DownlinkNASTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem DownlinkNASTransportIEField
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

// MarshalAPER encodes PWSFailureIndication to APER format.
func (v *PWSFailureIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PWSFailureIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes PWSFailureIndication from APER format.
func (v *PWSFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PWSFailureIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PWSFailureIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PWSFailureIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSFailureIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "PWSFailureIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "PWSFailureIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PWSFailureIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PWSFailureIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(PWSFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PWSFailureIndicationIEField
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *DownlinkNASTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "DownlinkNASTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "DownlinkNASTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v DownlinkNASTransport) WithoutReplay() DownlinkNASTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero DownlinkNASTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PWSFailureIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PWSFailureIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PWSFailureIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PWSFailureIndication) WithoutReplay() PWSFailureIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PWSFailureIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextReleaseRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseRequest) WithoutReplay() UEContextReleaseRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *DownlinkNASTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *DownlinkNASTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *DownlinkNASTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("DownlinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("DownlinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PWSFailureIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PWSFailureIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PWSFailureIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PWSFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PWSFailureIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PWSFailureIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PWSFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextReleaseRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *DownlinkNASTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "DownlinkNASTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *DownlinkNASTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "DownlinkNASTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APDownlinkNASTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "DownlinkNASTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "DownlinkNASTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *DownlinkNASTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "DownlinkNASTransport")
}
func (v *DownlinkNASTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "DownlinkNASTransport")
}
func (v *DownlinkNASTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APDownlinkNASTransport(v, &s)
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
func (v *DownlinkNASTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *DownlinkNASTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PWSFailureIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PWSFailureIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PWSFailureIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PWSFailureIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPWSFailureIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PWSFailureIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PWSFailureIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PWSFailureIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PWSFailureIndication")
}
func (v *PWSFailureIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PWSFailureIndication")
}
func (v *PWSFailureIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPWSFailureIndication(v, &s)
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
func (v *PWSFailureIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PWSFailureIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextReleaseRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseRequest")
}
func (v *UEContextReleaseRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseRequest")
}
func (v *UEContextReleaseRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseRequest(v, &s)
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
func (v *UEContextReleaseRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *DownlinkNASTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "DownlinkNASTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded DownlinkNASTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APDownlinkNASTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = DownlinkNASTransport{}
		return report, aper.OperationError(err, "DownlinkNASTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "DownlinkNASTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *PWSFailureIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PWSFailureIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PWSFailureIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPWSFailureIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PWSFailureIndication{}
		return report, aper.OperationError(err, "PWSFailureIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PWSFailureIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextReleaseRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseRequest{}
		return report, aper.OperationError(err, "UEContextReleaseRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseRequest")
}

// RequestedCellListComplete carries a complete RequestedCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type RequestedCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.RequestedCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *RequestedCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERRequestedCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes RequestedCellList from APER format.
func (v *RequestedCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RequestedCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestedCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	value, err := BridgeUnmarshalAPERRequestedCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "RequestedCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERRequestedCellList encodes a RequestedCellList list to APER.
func BridgeMarshalAPERRequestedCellList(list RequestedCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERRequestedCellList decodes a RequestedCellList list from APER.
func BridgeUnmarshalAPERRequestedCellList(data []byte) (RequestedCellListComplete, error) {
	var value RequestedCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERRequestedCellListFrom decodes a RequestedCellList list from bb.
func BridgeUnmarshalAPERRequestedCellListFrom(bb *aper.BitBuffer) (s20.RequestedCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERRequestedCellListListValue
	if err := BridgeUnmarshalAPERRequestedCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERRequestedCellListInto(v *s21.BridgeAsn1cAPERRequestedCellListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s20.RequestedCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s18.IRATCellID
			if err := s18.BridgeIRATCellIDMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
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
	return nil
}

// ReportingCellListComplete carries a complete ReportingCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ReportingCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s20.ReportingCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *ReportingCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERReportingCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ReportingCellList from APER format.
func (v *ReportingCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ReportingCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ReportingCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	value, err := BridgeUnmarshalAPERReportingCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ReportingCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ReportingCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERReportingCellList encodes a ReportingCellList list to APER.
func BridgeMarshalAPERReportingCellList(list ReportingCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERReportingCellList decodes a ReportingCellList list from APER.
func BridgeUnmarshalAPERReportingCellList(data []byte) (ReportingCellListComplete, error) {
	var value ReportingCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERReportingCellListFrom decodes a ReportingCellList list from bb.
func BridgeUnmarshalAPERReportingCellListFrom(bb *aper.BitBuffer) (s20.ReportingCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERReportingCellListListValue
	if err := BridgeUnmarshalAPERReportingCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERReportingCellListInto(v *s21.BridgeAsn1cAPERReportingCellListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s20.ReportingCellList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 128, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s20.ReportingCellListItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s20.BridgeReportingCellListItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// NotificationCellListComplete carries a complete NotificationCellList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type NotificationCellListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s19.NotificationCellList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *NotificationCellListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMarshalAPERNotificationCellListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes NotificationCellList from APER format.
func (v *NotificationCellListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NotificationCellList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NotificationCellListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	value, err := BridgeUnmarshalAPERNotificationCellListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	padding, err := aper.CaptureFinalBits(bb, "NotificationCellList")
	if err != nil {
		return runtime.WrapDecodePath(err, "NotificationCellList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERNotificationCellList encodes a NotificationCellList list to APER.
func BridgeMarshalAPERNotificationCellList(list NotificationCellListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERNotificationCellList decodes a NotificationCellList list from APER.
func BridgeUnmarshalAPERNotificationCellList(data []byte) (NotificationCellListComplete, error) {
	var value NotificationCellListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERNotificationCellListFrom decodes a NotificationCellList list from bb.
func BridgeUnmarshalAPERNotificationCellListFrom(bb *aper.BitBuffer) (s19.NotificationCellList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s21.BridgeAsn1cAPERNotificationCellListListValue
	if err := s41.BridgeUnmarshalAPERNotificationCellListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NotificationCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "NotificationCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "NotificationCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NotificationCellListComplete) WithoutReplay() NotificationCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero NotificationCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ReportingCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ReportingCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ReportingCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ReportingCellListComplete) WithoutReplay() ReportingCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ReportingCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RequestedCellListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RequestedCellListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RequestedCellListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RequestedCellListComplete) WithoutReplay() RequestedCellListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RequestedCellListComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *NotificationCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "NotificationCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *NotificationCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NotificationCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APNotificationCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "NotificationCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "NotificationCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *NotificationCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "NotificationCellListComplete")
}
func (v *NotificationCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "NotificationCellListComplete")
}
func (v *NotificationCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APNotificationCellListComplete(v, &s)
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
func (v *NotificationCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *NotificationCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERNotificationCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *ReportingCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ReportingCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ReportingCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ReportingCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APReportingCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ReportingCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ReportingCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ReportingCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ReportingCellListComplete")
}
func (v *ReportingCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ReportingCellListComplete")
}
func (v *ReportingCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APReportingCellListComplete(v, &s)
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
func (v *ReportingCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ReportingCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERReportingCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *RequestedCellListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RequestedCellListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RequestedCellListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RequestedCellListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRequestedCellListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RequestedCellListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RequestedCellListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RequestedCellListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RequestedCellListComplete")
}
func (v *RequestedCellListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RequestedCellListComplete")
}
func (v *RequestedCellListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRequestedCellListComplete(v, &s)
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
func (v *RequestedCellListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RequestedCellListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s25.BridgeMarshalAPERRequestedCellListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *NotificationCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NotificationCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded NotificationCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APNotificationCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = NotificationCellListComplete{}
		return report, aper.OperationError(err, "NotificationCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NotificationCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ReportingCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ReportingCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ReportingCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APReportingCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ReportingCellListComplete{}
		return report, aper.OperationError(err, "ReportingCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ReportingCellListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *RequestedCellListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RequestedCellListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RequestedCellListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRequestedCellListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RequestedCellListComplete{}
		return report, aper.OperationError(err, "RequestedCellListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RequestedCellListComplete")
}

// MarshalAPERRequestedCellList encodes a complete named list.
func MarshalAPERRequestedCellList(v RequestedCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERReportingCellList encodes a complete named list.
func MarshalAPERReportingCellList(v ReportingCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERNotificationCellList encodes a complete named list.
func MarshalAPERNotificationCellList(v NotificationCellListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERRequestedCellList decodes a complete named list.
func UnmarshalAPERRequestedCellList(data []byte, options ...aper.DecodeOption) (RequestedCellListComplete, aper.DecodeReport, error) {
	var v RequestedCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERReportingCellList decodes a complete named list.
func UnmarshalAPERReportingCellList(data []byte, options ...aper.DecodeOption) (ReportingCellListComplete, aper.DecodeReport, error) {
	var v ReportingCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERNotificationCellList decodes a complete named list.
func UnmarshalAPERNotificationCellList(data []byte, options ...aper.DecodeOption) (NotificationCellListComplete, aper.DecodeReport, error) {
	var v NotificationCellListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type HandoverRestrictionListExtIEsValue struct {
	id                                  s00.ProtocolIEID
	received                            aper.WireSpan
	replay                              aper.Snapshot
	opaque                              aper.OpaqueOpenType
	isOpaque                            bool
	rowNRrestrictioninEPSasSecondaryRAT *s00.NRrestrictioninEPSasSecondaryRAT
	rowUnlicensedSpectrumRestriction    *s00.UnlicensedSpectrumRestriction
	rowCNTypeRestrictions               *s14.CNTypeRestrictions
	rowNRrestrictionin5GS               *s00.NRrestrictionin5GS
	rowLastNGRANPLMNIdentity            *s00.PLMNidentity
	rowRATRestrictions                  *s20.RATRestrictions
}

func (v HandoverRestrictionListExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(261):
		return v.rowNRrestrictioninEPSasSecondaryRAT != nil
	case s00.ProtocolIEID(270):
		return v.rowUnlicensedSpectrumRestriction != nil
	case s00.ProtocolIEID(282):
		return v.rowCNTypeRestrictions != nil
	case s00.ProtocolIEID(287):
		return v.rowNRrestrictionin5GS != nil
	case s00.ProtocolIEID(290):
		return v.rowLastNGRANPLMNIdentity != nil
	case s00.ProtocolIEID(336):
		return v.rowRATRestrictions != nil
	}
	return false
}
func (v *HandoverRestrictionListExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (HandoverRestrictionListExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs"}}
}
func (HandoverRestrictionListExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(261):
		return aper.UnknownSelector
	case s00.ProtocolIEID(270):
		return aper.UnknownSelector
	case s00.ProtocolIEID(282):
		return aper.UnknownSelector
	case s00.ProtocolIEID(287):
		return aper.UnknownSelector
	case s00.ProtocolIEID(290):
		return aper.UnknownSelector
	case s00.ProtocolIEID(336):
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
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
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
func (v *HandoverRestrictionListExtIEsValue) AsNRrestrictioninEPSasSecondaryRAT() (*s00.NRrestrictioninEPSasSecondaryRAT, bool) {
	if v == nil || v.id != s00.ProtocolIEID(261) || v.rowNRrestrictioninEPSasSecondaryRAT == nil {
		return nil, false
	}
	return v.rowNRrestrictioninEPSasSecondaryRAT, true
}
func (v *HandoverRestrictionListExtIEsValue) AsUnlicensedSpectrumRestriction() (*s00.UnlicensedSpectrumRestriction, bool) {
	if v == nil || v.id != s00.ProtocolIEID(270) || v.rowUnlicensedSpectrumRestriction == nil {
		return nil, false
	}
	return v.rowUnlicensedSpectrumRestriction, true
}
func (v *HandoverRestrictionListExtIEsValue) AsCNTypeRestrictions() (*s14.CNTypeRestrictions, bool) {
	if v == nil || v.id != s00.ProtocolIEID(282) || v.rowCNTypeRestrictions == nil {
		return nil, false
	}
	return v.rowCNTypeRestrictions, true
}
func (v *HandoverRestrictionListExtIEsValue) AsNRrestrictionin5GS() (*s00.NRrestrictionin5GS, bool) {
	if v == nil || v.id != s00.ProtocolIEID(287) || v.rowNRrestrictionin5GS == nil {
		return nil, false
	}
	return v.rowNRrestrictionin5GS, true
}
func (v *HandoverRestrictionListExtIEsValue) AsLastNGRANPLMNIdentity() (*s00.PLMNidentity, bool) {
	if v == nil || v.id != s00.ProtocolIEID(290) || v.rowLastNGRANPLMNIdentity == nil {
		return nil, false
	}
	return v.rowLastNGRANPLMNIdentity, true
}
func (v *HandoverRestrictionListExtIEsValue) AsRATRestrictions() (*s20.RATRestrictions, bool) {
	if v == nil || v.id != s00.ProtocolIEID(336) || v.rowRATRestrictions == nil {
		return nil, false
	}
	return v.rowRATRestrictions, true
}
func (v HandoverRestrictionListExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (HandoverRestrictionListExtIEsValue, error) {
	out := HandoverRestrictionListExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(261):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NRrestrictioninEPSasSecondaryRAT"})
		value := s00.NRrestrictioninEPSasSecondaryRAT(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NRrestrictioninEPSasSecondaryRAT:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNRrestrictioninEPSasSecondaryRAT = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(270):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UnlicensedSpectrumRestriction"})
		value := s00.UnlicensedSpectrumRestriction(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UnlicensedSpectrumRestriction:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUnlicensedSpectrumRestriction = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(282):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERCNTypeRestrictionsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CNTypeRestrictions:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowCNTypeRestrictions = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(287):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NRrestrictionin5GS"})
		value := s00.NRrestrictionin5GS(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NRrestrictionin5GS:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNRrestrictionin5GS = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(290):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.PLMNidentity, error) {
			var v struct{ Value s00.PLMNidentity }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.PLMNidentity(val_value)
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
		out.rowLastNGRANPLMNIdentity = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(336):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERRATRestrictionsFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RATRestrictions:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowRATRestrictions = &value
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
func (v HandoverRestrictionListExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v HandoverRestrictionListExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(261):
		if v.rowNRrestrictioninEPSasSecondaryRAT == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-NRrestrictioninEPSasSecondaryRAT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNRrestrictioninEPSasSecondaryRAT), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(270):
		if v.rowUnlicensedSpectrumRestriction == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-UnlicensedSpectrumRestriction:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUnlicensedSpectrumRestriction), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(282):
		if v.rowCNTypeRestrictions == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-CNTypeRestrictions:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.CNTypeRestrictionsComplete{Value: *v.rowCNTypeRestrictions}
		candidate, err := s38.BridgeCNTypeRestrictionsCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(287):
		if v.rowNRrestrictionin5GS == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-NRrestrictionin5GS:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNRrestrictionin5GS), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(290):
		if v.rowLastNGRANPLMNIdentity == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-LastNG-RANPLMNIdentity:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.PLMNidentity, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.PLMNidentity }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 3, 3, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowLastNGRANPLMNIdentity, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(336):
		if v.rowRATRestrictions == nil {
			return nil, fmt.Errorf("%s missing value", "HandoverRestrictionList-ExtIEs.id-RAT-Restrictions:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := RATRestrictionsComplete{Value: *v.rowRATRestrictions}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "HandoverRestrictionListExtIEsValue:", v.id)
	}
}

type DownlinkNASTransportIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowENBUES1APID                            *s00.ENBUES1APID
	rowNASPDU                                 *s00.NASPDU
	rowHandoverRestrictionList                *HandoverRestrictionList
	rowSubscriberProfileIDforRFP              *s00.SubscriberProfileIDforRFP
	rowSRVCCOperationPossible                 *s00.SRVCCOperationPossible
	rowUERadioCapability                      *s00.UERadioCapability
	rowDLNASPDUDeliveryAckRequest             *s00.DLNASPDUDeliveryAckRequest
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowNRUESecurityCapabilities               *s19.NRUESecurityCapabilities
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowUECapabilityInfoRequest                *s00.UECapabilityInfoRequest
	rowEndIndication                          *s00.EndIndication
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowSubscriptionBasedUEDifferentiationInfo *s30.SubscriptionBasedUEDifferentiationInfo
	rowAdditionalRRMPriorityIndex             *s00.AdditionalRRMPriorityIndex
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowMaskedIMEISV                           *s00.MaskedIMEISV
	rowCoarseUELocation                       *s00.CoarseUELocation
}

func (v DownlinkNASTransportIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(26):
		return v.rowNASPDU != nil
	case s00.ProtocolIEID(41):
		return v.rowHandoverRestrictionList != nil
	case s00.ProtocolIEID(106):
		return v.rowSubscriberProfileIDforRFP != nil
	case s00.ProtocolIEID(124):
		return v.rowSRVCCOperationPossible != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(249):
		return v.rowDLNASPDUDeliveryAckRequest != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(275):
		return v.rowUECapabilityInfoRequest != nil
	case s00.ProtocolIEID(280):
		return v.rowEndIndication != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	case s00.ProtocolIEID(354):
		return v.rowCoarseUELocation != nil
	}
	return false
}
func (v *DownlinkNASTransportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (DownlinkNASTransportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs"}}
}
func (DownlinkNASTransportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(26):
		return aper.UnknownSelector
	case s00.ProtocolIEID(41):
		return aper.UnknownSelector
	case s00.ProtocolIEID(106):
		return aper.UnknownSelector
	case s00.ProtocolIEID(124):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(249):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(275):
		return aper.UnknownSelector
	case s00.ProtocolIEID(280):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
		return aper.UnknownSelector
	case s00.ProtocolIEID(354):
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
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
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
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v *DownlinkNASTransportIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *DownlinkNASTransportIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *DownlinkNASTransportIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}
func (v *DownlinkNASTransportIEValue) AsHandoverRestrictionList() (*HandoverRestrictionList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(41) || v.rowHandoverRestrictionList == nil {
		return nil, false
	}
	return v.rowHandoverRestrictionList, true
}
func (v *DownlinkNASTransportIEValue) AsSubscriberProfileIDforRFP() (*s00.SubscriberProfileIDforRFP, bool) {
	if v == nil || v.id != s00.ProtocolIEID(106) || v.rowSubscriberProfileIDforRFP == nil {
		return nil, false
	}
	return v.rowSubscriberProfileIDforRFP, true
}
func (v *DownlinkNASTransportIEValue) AsSRVCCOperationPossible() (*s00.SRVCCOperationPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(124) || v.rowSRVCCOperationPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationPossible, true
}
func (v *DownlinkNASTransportIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}
func (v *DownlinkNASTransportIEValue) AsDLNASPDUDeliveryAckRequest() (*s00.DLNASPDUDeliveryAckRequest, bool) {
	if v == nil || v.id != s00.ProtocolIEID(249) || v.rowDLNASPDUDeliveryAckRequest == nil {
		return nil, false
	}
	return v.rowDLNASPDUDeliveryAckRequest, true
}
func (v *DownlinkNASTransportIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}
func (v *DownlinkNASTransportIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}
func (v *DownlinkNASTransportIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}
func (v *DownlinkNASTransportIEValue) AsUECapabilityInfoRequest() (*s00.UECapabilityInfoRequest, bool) {
	if v == nil || v.id != s00.ProtocolIEID(275) || v.rowUECapabilityInfoRequest == nil {
		return nil, false
	}
	return v.rowUECapabilityInfoRequest, true
}
func (v *DownlinkNASTransportIEValue) AsEndIndication() (*s00.EndIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(280) || v.rowEndIndication == nil {
		return nil, false
	}
	return v.rowEndIndication, true
}
func (v *DownlinkNASTransportIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}
func (v *DownlinkNASTransportIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}
func (v *DownlinkNASTransportIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}
func (v *DownlinkNASTransportIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}
func (v *DownlinkNASTransportIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}
func (v *DownlinkNASTransportIEValue) AsCoarseUELocation() (*s00.CoarseUELocation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(354) || v.rowCoarseUELocation == nil {
		return nil, false
	}
	return v.rowCoarseUELocation, true
}
func (v DownlinkNASTransportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (DownlinkNASTransportIEValue, error) {
	out := DownlinkNASTransportIEValue{id: id}
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
	case s00.ProtocolIEID(41):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value HandoverRestrictionList
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "HandoverRestrictionList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRestrictionList")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowHandoverRestrictionList = &value
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
	case s00.ProtocolIEID(249):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DLNASPDUDeliveryAckRequest"})
		value := s00.DLNASPDUDeliveryAckRequest(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DLNASPDUDeliveryAckRequest:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDLNASPDUDeliveryAckRequest = &value
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
	case s00.ProtocolIEID(275):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UECapabilityInfoRequest"})
		value := s00.UECapabilityInfoRequest(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UECapabilityInfoRequest:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUECapabilityInfoRequest = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(280):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EndIndication"})
		value := s00.EndIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EndIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEndIndication = &value
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
		var value s30.SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(&value) = padding
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(&value))
		*s30.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(&value) = raw.ContentLocation()
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v DownlinkNASTransportIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v DownlinkNASTransportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-eNB-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-NAS-PDU:")
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
	case s00.ProtocolIEID(41):
		if v.rowHandoverRestrictionList == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-HandoverRestrictionList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowHandoverRestrictionList.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(106):
		if v.rowSubscriberProfileIDforRFP == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-SubscriberProfileIDforRFP:")
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
	case s00.ProtocolIEID(124):
		if v.rowSRVCCOperationPossible == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-SRVCCOperationPossible:")
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
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-UERadioCapability:")
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
	case s00.ProtocolIEID(249):
		if v.rowDLNASPDUDeliveryAckRequest == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-DLNASPDUDeliveryAckRequest:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowDLNASPDUDeliveryAckRequest), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-EnhancedCoverageRestricted:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-NRUESecurityCapabilities:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-CE-ModeBRestricted:")
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
	case s00.ProtocolIEID(275):
		if v.rowUECapabilityInfoRequest == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-UECapabilityInfoRequest:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUECapabilityInfoRequest), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(280):
		if v.rowEndIndication == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-EndIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEndIndication), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-PendingDataIndication:")
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
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s30.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-AdditionalRRMPriorityIndex:")
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
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-UERadioCapabilityID:")
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
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-Masked-IMEISV:")
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
	case s00.ProtocolIEID(354):
		if v.rowCoarseUELocation == nil {
			return nil, fmt.Errorf("%s missing value", "DownlinkNASTransport-IEs.id-CoarseUELocation:")
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "DownlinkNASTransportIEValue:", v.id)
	}
}

type PWSFailureIndicationIEValue struct {
	id                   s00.ProtocolIEID
	received             aper.WireSpan
	replay               aper.Snapshot
	opaque               aper.OpaqueOpenType
	isOpaque             bool
	rowPWSfailedECGIList *s20.PWSfailedECGIList
	rowGlobalENBID       *s18.GlobalENBID
}

func (v PWSFailureIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(222):
		return v.rowPWSfailedECGIList != nil
	case s00.ProtocolIEID(59):
		return v.rowGlobalENBID != nil
	}
	return false
}
func (v *PWSFailureIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PWSFailureIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSFailureIndicationIEs"}}
}
func (PWSFailureIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(222):
		return aper.UnknownSelector
	case s00.ProtocolIEID(59):
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
func (v *PWSFailureIndicationIEValue) AsPWSfailedECGIList() (*s20.PWSfailedECGIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(222) || v.rowPWSfailedECGIList == nil {
		return nil, false
	}
	return v.rowPWSfailedECGIList, true
}
func (v *PWSFailureIndicationIEValue) AsGlobalENBID() (*s18.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}
func (v PWSFailureIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PWSFailureIndicationIEValue, error) {
	out := PWSFailureIndicationIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(222):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERPWSfailedECGIListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PWSfailedECGIList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowPWSfailedECGIList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(59):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GlobalENBID
		child := scope
		if err := s18.BridgeGlobalENBIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GlobalENBID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalENBID")
		if err != nil {
			return out, err
		}
		*s18.BridgeGlobalENBIDFieldPerPadding(&value) = padding
		*s18.BridgeGlobalENBIDFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGlobalENBIDFieldReceivedBytes(&value))
		*s18.BridgeGlobalENBIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowGlobalENBID = &value
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
func (v PWSFailureIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PWSFailureIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(222):
		if v.rowPWSfailedECGIList == nil {
			return nil, fmt.Errorf("%s missing value", "PWSFailureIndicationIEs.id-PWSfailedECGIList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := PWSfailedECGIListComplete{Value: *v.rowPWSfailedECGIList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(59):
		if v.rowGlobalENBID == nil {
			return nil, fmt.Errorf("%s missing value", "PWSFailureIndicationIEs.id-Global-ENB-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PWSFailureIndicationIEValue:", v.id)
	}
}

type UEContextReleaseRequestIEValue struct {
	id                                 s00.ProtocolIEID
	received                           aper.WireSpan
	replay                             aper.Snapshot
	opaque                             aper.OpaqueOpenType
	isOpaque                           bool
	rowMMEUES1APID                     *s00.MMEUES1APID
	rowENBUES1APID                     *s00.ENBUES1APID
	rowCause                           *s14.Cause
	rowGWContextReleaseIndication      *s00.GWContextReleaseIndication
	rowSecondaryRATDataUsageReportList *s28.SecondaryRATDataUsageReportList
}

func (v UEContextReleaseRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(164):
		return v.rowGWContextReleaseIndication != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	}
	return false
}
func (v *UEContextReleaseRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextReleaseRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs"}}
}
func (UEContextReleaseRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(164):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
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
func (v *UEContextReleaseRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}
func (v *UEContextReleaseRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}
func (v *UEContextReleaseRequestIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v *UEContextReleaseRequestIEValue) AsGWContextReleaseIndication() (*s00.GWContextReleaseIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(164) || v.rowGWContextReleaseIndication == nil {
		return nil, false
	}
	return v.rowGWContextReleaseIndication, true
}
func (v *UEContextReleaseRequestIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}
func (v UEContextReleaseRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextReleaseRequestIEValue, error) {
	out := UEContextReleaseRequestIEValue{id: id}
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
	case s00.ProtocolIEID(164):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "GWContextReleaseIndication"})
		value := s00.GWContextReleaseIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "GWContextReleaseIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowGWContextReleaseIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SecondaryRATDataUsageReportList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowSecondaryRATDataUsageReportList = &value
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
func (v UEContextReleaseRequestIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextReleaseRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseRequest-IEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseRequest-IEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseRequest-IEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(164):
		if v.rowGWContextReleaseIndication == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseRequest-IEs.id-GWContextReleaseIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowGWContextReleaseIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseRequest-IEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextReleaseRequestIEValue:", v.id)
	}
}

type HandoverRestrictionListExtIETable struct{}

func HandoverRestrictionListExtIEs() HandoverRestrictionListExtIETable {
	return HandoverRestrictionListExtIETable{}
}
func (HandoverRestrictionListExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs"}
		return sealed
	}()
}
func (HandoverRestrictionListExtIETable) Table() s00.HandoverRestrictionListExtIEsValueExtensionTable {
	return func() s00.HandoverRestrictionListExtIEsValueExtensionTable {
		sealed := s00.HandoverRestrictionListExtIEsValueExtensionTable{}
		*s00.BridgeHandoverRestrictionListExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverRestrictionListExtIETable) infoNRrestrictioninEPSasSecondaryRAT() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(261), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRrestrictioninEPSasSecondaryRAT"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-NRrestrictioninEPSasSecondaryRAT"}}}
}
func (t HandoverRestrictionListExtIETable) NRrestrictioninEPSasSecondaryRAT() HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding {
	return HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding{info: t.infoNRrestrictioninEPSasSecondaryRAT(), codec: func() s01.NRrestrictioninEPSasSecondaryRATValueCodec {
		sealed := s01.NRrestrictioninEPSasSecondaryRATValueCodec{}
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldPath(&sealed) = "NRrestrictioninEPSasSecondaryRAT"
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRrestrictioninEPSasSecondaryRAT, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NRrestrictioninEPSasSecondaryRAT
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(261), raw)
			if err != nil {
				var empty s00.NRrestrictioninEPSasSecondaryRAT
				return empty, err
			}
			value, ok := decoded.AsNRrestrictioninEPSasSecondaryRAT()
			if !ok {
				var empty s00.NRrestrictioninEPSasSecondaryRAT
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-NRrestrictioninEPSasSecondaryRAT: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldEncode(&sealed) = func(value s00.NRrestrictioninEPSasSecondaryRAT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(261), rowNRrestrictioninEPSasSecondaryRAT: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldCapture(&sealed) = func(v s00.NRrestrictioninEPSasSecondaryRAT, options aper.DecodeState) (s00.NRrestrictioninEPSasSecondaryRAT, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNRrestrictioninEPSasSecondaryRAT(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldCompare(&sealed) = func(v s00.NRrestrictioninEPSasSecondaryRAT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNRrestrictioninEPSasSecondaryRAT(&v,
				&s,
			)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRrestrictioninEPSasSecondaryRAT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NRrestrictioninEPSasSecondaryRAT) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(261), rowNRrestrictioninEPSasSecondaryRAT: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s00.NRrestrictioninEPSasSecondaryRAT, bool) {
			return value.AsNRrestrictioninEPSasSecondaryRAT()
		}}
}
func (HandoverRestrictionListExtIETable) infoUnlicensedSpectrumRestriction() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(270), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UnlicensedSpectrumRestriction"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-UnlicensedSpectrumRestriction"}}}
}
func (t HandoverRestrictionListExtIETable) UnlicensedSpectrumRestriction() HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding {
	return HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding{info: t.infoUnlicensedSpectrumRestriction(), codec: func() s02.UnlicensedSpectrumRestrictionValueCodec {
		sealed := s02.UnlicensedSpectrumRestrictionValueCodec{}
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldPath(&sealed) = "UnlicensedSpectrumRestriction"
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UnlicensedSpectrumRestriction, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UnlicensedSpectrumRestriction
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(270), raw)
			if err != nil {
				var empty s00.UnlicensedSpectrumRestriction
				return empty, err
			}
			value, ok := decoded.AsUnlicensedSpectrumRestriction()
			if !ok {
				var empty s00.UnlicensedSpectrumRestriction
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-UnlicensedSpectrumRestriction: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldEncode(&sealed) = func(value s00.UnlicensedSpectrumRestriction, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(270), rowUnlicensedSpectrumRestriction: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldCapture(&sealed) = func(v s00.UnlicensedSpectrumRestriction, options aper.DecodeState) (s00.UnlicensedSpectrumRestriction, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUnlicensedSpectrumRestriction(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldCompare(&sealed) = func(v s00.UnlicensedSpectrumRestriction, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s07.BridgeCompareS1APUnlicensedSpectrumRestriction(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUnlicensedSpectrumRestrictionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UnlicensedSpectrumRestriction"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UnlicensedSpectrumRestriction) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(270), rowUnlicensedSpectrumRestriction: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s00.UnlicensedSpectrumRestriction, bool) {
			return value.AsUnlicensedSpectrumRestriction()
		}}
}
func (HandoverRestrictionListExtIETable) infoCNTypeRestrictions() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(282), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CNTypeRestrictions"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-CNTypeRestrictions"}}}
}
func (t HandoverRestrictionListExtIETable) CNTypeRestrictions() HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding {
	return HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding{info: t.infoCNTypeRestrictions(), codec: func() s14.CNTypeRestrictionsValueCodec {
		sealed := s14.CNTypeRestrictionsValueCodec{}
		*s14.BridgeCNTypeRestrictionsValueCodecFieldPath(&sealed) = "CNTypeRestrictions"
		*s14.BridgeCNTypeRestrictionsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.CNTypeRestrictions, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.CNTypeRestrictions
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(282), raw)
			if err != nil {
				var empty s14.CNTypeRestrictions
				return empty, err
			}
			value, ok := decoded.AsCNTypeRestrictions()
			if !ok {
				var empty s14.CNTypeRestrictions
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-CNTypeRestrictions: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCNTypeRestrictionsValueCodecFieldEncode(&sealed) = func(value s14.CNTypeRestrictions, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(282), rowCNTypeRestrictions: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCNTypeRestrictionsValueCodecFieldCapture(&sealed) = func(v s14.CNTypeRestrictions, options aper.DecodeState) (s14.CNTypeRestrictions, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APCNTypeRestrictions(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s14.BridgeCNTypeRestrictionsValueCodecFieldCompare(&sealed) = func(v s14.CNTypeRestrictions, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s21.BridgeCompareS1APCNTypeRestrictions(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCNTypeRestrictionsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNTypeRestrictions"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.CNTypeRestrictions) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(282), rowCNTypeRestrictions: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s14.CNTypeRestrictions, bool) {
			return value.AsCNTypeRestrictions()
		}}
}
func (HandoverRestrictionListExtIETable) infoNRrestrictionin5GS() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(287), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRrestrictionin5GS"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-NRrestrictionin5GS"}}}
}
func (t HandoverRestrictionListExtIETable) NRrestrictionin5GS() HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding {
	return HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding{info: t.infoNRrestrictionin5GS(), codec: func() s01.NRrestrictionin5GSValueCodec {
		sealed := s01.NRrestrictionin5GSValueCodec{}
		*s01.BridgeNRrestrictionin5GSValueCodecFieldPath(&sealed) = "NRrestrictionin5GS"
		*s01.BridgeNRrestrictionin5GSValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRrestrictionin5GS, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NRrestrictionin5GS
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(287), raw)
			if err != nil {
				var empty s00.NRrestrictionin5GS
				return empty, err
			}
			value, ok := decoded.AsNRrestrictionin5GS()
			if !ok {
				var empty s00.NRrestrictionin5GS
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-NRrestrictionin5GS: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNRrestrictionin5GSValueCodecFieldEncode(&sealed) = func(value s00.NRrestrictionin5GS, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(287), rowNRrestrictionin5GS: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNRrestrictionin5GSValueCodecFieldCapture(&sealed) = func(v s00.NRrestrictionin5GS, options aper.DecodeState) (s00.NRrestrictionin5GS, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNRrestrictionin5GS(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeNRrestrictionin5GSValueCodecFieldCompare(&sealed) = func(v s00.NRrestrictionin5GS, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNRrestrictionin5GS(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNRrestrictionin5GSValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRrestrictionin5GS"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NRrestrictionin5GS) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(287), rowNRrestrictionin5GS: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s00.NRrestrictionin5GS, bool) {
			return value.AsNRrestrictionin5GS()
		}}
}
func (HandoverRestrictionListExtIETable) infoLastNGRANPLMNIdentity() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(290), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PLMNidentity"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-LastNG-RANPLMNIdentity"}}}
}
func (t HandoverRestrictionListExtIETable) LastNGRANPLMNIdentity() HandoverRestrictionListExtIEsPLMNidentityExtBinding {
	return HandoverRestrictionListExtIEsPLMNidentityExtBinding{info: t.infoLastNGRANPLMNIdentity(), codec: func() s01.PLMNidentityValueCodec {
		sealed := s01.PLMNidentityValueCodec{}
		*s01.BridgePLMNidentityValueCodecFieldPath(&sealed) = "PLMNidentity"
		*s01.BridgePLMNidentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PLMNidentity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PLMNidentity
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(290), raw)
			if err != nil {
				var empty s00.PLMNidentity
				return empty, err
			}
			value, ok := decoded.AsLastNGRANPLMNIdentity()
			if !ok {
				var empty s00.PLMNidentity
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-LastNG-RANPLMNIdentity: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePLMNidentityValueCodecFieldEncode(&sealed) = func(value s00.PLMNidentity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(290), rowLastNGRANPLMNIdentity: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePLMNidentityValueCodecFieldCapture(&sealed) = func(v s00.PLMNidentity, options aper.DecodeState) (s00.PLMNidentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPLMNidentity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePLMNidentityValueCodecFieldCompare(&sealed) = func(v s00.PLMNidentity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APPLMNidentity(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgePLMNidentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PLMNidentity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PLMNidentity) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(290), rowLastNGRANPLMNIdentity: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s00.PLMNidentity, bool) {
			return value.AsLastNGRANPLMNIdentity()
		}}
}
func (HandoverRestrictionListExtIETable) infoRATRestrictions() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: HandoverRestrictionListExtIEs().ID(), ID: s00.ProtocolExtensionID(336), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RAT-Restrictions"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList-ExtIEs", Row: "id-RAT-Restrictions"}}}
}
func (t HandoverRestrictionListExtIETable) RATRestrictions() HandoverRestrictionListExtIEsRATRestrictionsExtBinding {
	return HandoverRestrictionListExtIEsRATRestrictionsExtBinding{info: t.infoRATRestrictions(), codec: func() s20.RATRestrictionsValueCodec {
		sealed := s20.RATRestrictionsValueCodec{}
		*s20.BridgeRATRestrictionsValueCodecFieldPath(&sealed) = "RATRestrictions"
		*s20.BridgeRATRestrictionsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.RATRestrictions, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.RATRestrictions
				return empty, err
			}
			var zero HandoverRestrictionListExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(336), raw)
			if err != nil {
				var empty s20.RATRestrictions
				return empty, err
			}
			value, ok := decoded.AsRATRestrictions()
			if !ok {
				var empty s20.RATRestrictions
				return empty, fmt.Errorf("binding HandoverRestrictionList-ExtIEs.id-RAT-Restrictions: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeRATRestrictionsValueCodecFieldEncode(&sealed) = func(value s20.RATRestrictions, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(336), rowRATRestrictions: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeRATRestrictionsValueCodecFieldCapture(&sealed) = func(v s20.RATRestrictions, options aper.DecodeState) (s20.RATRestrictions, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APRATRestrictions(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeRATRestrictionsValueCodecFieldCompare(&sealed) = func(v s20.RATRestrictions, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APRATRestrictions(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeRATRestrictionsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RATRestrictions"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.RATRestrictions) HandoverRestrictionListExtIEsValue {
			return HandoverRestrictionListExtIEsValue{id: s00.ProtocolIEID(336), rowRATRestrictions: &value}
		}, get: func(value *HandoverRestrictionListExtIEsValue) (*s20.RATRestrictions, bool) {
			return value.AsRATRestrictions()
		}}
}
func (t HandoverRestrictionListExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (HandoverRestrictionListExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(261):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-NRrestrictioninEPSasSecondaryRAT requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(270):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-UnlicensedSpectrumRestriction requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(282):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-CNTypeRestrictions requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(287):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-NRrestrictionin5GS requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(290):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-LastNG-RANPLMNIdentity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(336):
		return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-RAT-Restrictions requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return HandoverRestrictionListExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return HandoverRestrictionListExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: HandoverRestrictionListExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type DownlinkNASTransportIETable struct{}

func DownlinkNASTransportIEs() DownlinkNASTransportIETable { return DownlinkNASTransportIETable{} }
func (DownlinkNASTransportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs"}
		return sealed
	}()
}
func (DownlinkNASTransportIETable) Table() s00.DownlinkNASTransportIEValueIETable {
	return func() s00.DownlinkNASTransportIEValueIETable {
		sealed := s00.DownlinkNASTransportIEValueIETable{}
		*s00.BridgeDownlinkNASTransportIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (DownlinkNASTransportIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t DownlinkNASTransportIETable) MMEUES1APID() DownlinkNASTransportMMEUES1APIDIEBinding {
	return DownlinkNASTransportMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (DownlinkNASTransportIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t DownlinkNASTransportIETable) ENBUES1APID() DownlinkNASTransportENBUES1APIDIEBinding {
	return DownlinkNASTransportENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (DownlinkNASTransportIETable) infoNASPDU() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(26), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NAS-PDU"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-NAS-PDU"}}}
}
func (t DownlinkNASTransportIETable) NASPDU() DownlinkNASTransportNASPDUIEBinding {
	return DownlinkNASTransportNASPDUIEBinding{info: t.infoNASPDU(), codec: func() s01.NASPDUValueCodec {
		sealed := s01.NASPDUValueCodec{}
		*s01.BridgeNASPDUValueCodecFieldPath(&sealed) = "NASPDU"
		*s01.BridgeNASPDUValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASPDU, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(26), raw)
			if err != nil {
				var empty s00.NASPDU
				return empty, err
			}
			value, ok := decoded.AsNASPDU()
			if !ok {
				var empty s00.NASPDU
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-NAS-PDU: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNASPDUValueCodecFieldEncode(&sealed) = func(value s00.NASPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.NASPDU) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(26), rowNASPDU: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.NASPDU, bool) { return value.AsNASPDU() }}
}
func (DownlinkNASTransportIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-HandoverRestrictionList"}}}
}
func (t DownlinkNASTransportIETable) HandoverRestrictionList() DownlinkNASTransportHandoverRestrictionListIEBinding {
	return DownlinkNASTransportHandoverRestrictionListIEBinding{info: t.infoHandoverRestrictionList(), codec: HandoverRestrictionListValueCodec{path: "HandoverRestrictionList",
		decode: func(data []byte, options aper.DecodeState) (HandoverRestrictionList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty HandoverRestrictionList
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(41), raw)
			if err != nil {
				var empty HandoverRestrictionList
				return empty, err
			}
			value, ok := decoded.AsHandoverRestrictionList()
			if !ok {
				var empty HandoverRestrictionList
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-HandoverRestrictionList: no selected value")
			}
			return *value, nil
		},
		encode: func(value HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}).encodeFresh(fresh, budget)
		}, capture: func(v HandoverRestrictionList, options aper.DecodeState) (HandoverRestrictionList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APHandoverRestrictionList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHandoverRestrictionList(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value HandoverRestrictionList) DownlinkNASTransportIEValue {
		return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}
	}, get: func(value *DownlinkNASTransportIEValue) (*HandoverRestrictionList, bool) {
		return value.AsHandoverRestrictionList()
	}}
}
func (DownlinkNASTransportIETable) infoSubscriberProfileIDforRFP() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(106), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SubscriberProfileIDforRFP"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-SubscriberProfileIDforRFP"}}}
}
func (t DownlinkNASTransportIETable) SubscriberProfileIDforRFP() DownlinkNASTransportSubscriberProfileIDforRFPIEBinding {
	return DownlinkNASTransportSubscriberProfileIDforRFPIEBinding{info: t.infoSubscriberProfileIDforRFP(), codec: func() s01.SubscriberProfileIDforRFPValueCodec {
		sealed := s01.SubscriberProfileIDforRFPValueCodec{}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldPath(&sealed) = "SubscriberProfileIDforRFP"
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(106), raw)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			value, ok := decoded.AsSubscriberProfileIDforRFP()
			if !ok {
				var empty s00.SubscriberProfileIDforRFP
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-SubscriberProfileIDforRFP: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&sealed) = func(value s00.SubscriberProfileIDforRFP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.SubscriberProfileIDforRFP) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
			return value.AsSubscriberProfileIDforRFP()
		}}
}
func (DownlinkNASTransportIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-SRVCCOperationPossible"}}}
}
func (t DownlinkNASTransportIETable) SRVCCOperationPossible() DownlinkNASTransportSRVCCOperationPossibleIEBinding {
	return DownlinkNASTransportSRVCCOperationPossibleIEBinding{info: t.infoSRVCCOperationPossible(), codec: func() s01.SRVCCOperationPossibleValueCodec {
		sealed := s01.SRVCCOperationPossibleValueCodec{}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(124), raw)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			value, ok := decoded.AsSRVCCOperationPossible()
			if !ok {
				var empty s00.SRVCCOperationPossible
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-SRVCCOperationPossible: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.SRVCCOperationPossible) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}}
}
func (DownlinkNASTransportIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-UERadioCapability"}}}
}
func (t DownlinkNASTransportIETable) UERadioCapability() DownlinkNASTransportUERadioCapabilityIEBinding {
	return DownlinkNASTransportUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.UERadioCapability) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (DownlinkNASTransportIETable) infoDLNASPDUDeliveryAckRequest() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(249), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DLNASPDUDeliveryAckRequest"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-DLNASPDUDeliveryAckRequest"}}}
}
func (t DownlinkNASTransportIETable) DLNASPDUDeliveryAckRequest() DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding {
	return DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding{info: t.infoDLNASPDUDeliveryAckRequest(), codec: func() s00.DLNASPDUDeliveryAckRequestValueCodec {
		sealed := s00.DLNASPDUDeliveryAckRequestValueCodec{}
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldPath(&sealed) = "DLNASPDUDeliveryAckRequest"
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DLNASPDUDeliveryAckRequest, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DLNASPDUDeliveryAckRequest
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(249), raw)
			if err != nil {
				var empty s00.DLNASPDUDeliveryAckRequest
				return empty, err
			}
			value, ok := decoded.AsDLNASPDUDeliveryAckRequest()
			if !ok {
				var empty s00.DLNASPDUDeliveryAckRequest
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-DLNASPDUDeliveryAckRequest: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldEncode(&sealed) = func(value s00.DLNASPDUDeliveryAckRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(249), rowDLNASPDUDeliveryAckRequest: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldCapture(&sealed) = func(v s00.DLNASPDUDeliveryAckRequest, options aper.DecodeState) (s00.DLNASPDUDeliveryAckRequest, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APDLNASPDUDeliveryAckRequest(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldCompare(&sealed) = func(v s00.DLNASPDUDeliveryAckRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDLNASPDUDeliveryAckRequest(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDLNASPDUDeliveryAckRequestValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLNASPDUDeliveryAckRequest"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DLNASPDUDeliveryAckRequest) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(249), rowDLNASPDUDeliveryAckRequest: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.DLNASPDUDeliveryAckRequest, bool) {
			return value.AsDLNASPDUDeliveryAckRequest()
		}}
}
func (DownlinkNASTransportIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-EnhancedCoverageRestricted"}}}
}
func (t DownlinkNASTransportIETable) EnhancedCoverageRestricted() DownlinkNASTransportEnhancedCoverageRestrictedIEBinding {
	return DownlinkNASTransportEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.EnhancedCoverageRestricted) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (DownlinkNASTransportIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-NRUESecurityCapabilities"}}}
}
func (t DownlinkNASTransportIETable) NRUESecurityCapabilities() DownlinkNASTransportNRUESecurityCapabilitiesIEBinding {
	return DownlinkNASTransportNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s19.NRUESecurityCapabilitiesValueCodec {
		sealed := s19.NRUESecurityCapabilitiesValueCodec{}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s19.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s19.NRUESecurityCapabilities) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (DownlinkNASTransportIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-CE-ModeBRestricted"}}}
}
func (t DownlinkNASTransportIETable) CEModeBRestricted() DownlinkNASTransportCEModeBRestrictedIEBinding {
	return DownlinkNASTransportCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CEModeBRestricted) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}}
}
func (DownlinkNASTransportIETable) infoUECapabilityInfoRequest() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(275), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UECapabilityInfoRequest"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-UECapabilityInfoRequest"}}}
}
func (t DownlinkNASTransportIETable) UECapabilityInfoRequest() DownlinkNASTransportUECapabilityInfoRequestIEBinding {
	return DownlinkNASTransportUECapabilityInfoRequestIEBinding{info: t.infoUECapabilityInfoRequest(), codec: func() s02.UECapabilityInfoRequestValueCodec {
		sealed := s02.UECapabilityInfoRequestValueCodec{}
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldPath(&sealed) = "UECapabilityInfoRequest"
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UECapabilityInfoRequest, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UECapabilityInfoRequest
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(275), raw)
			if err != nil {
				var empty s00.UECapabilityInfoRequest
				return empty, err
			}
			value, ok := decoded.AsUECapabilityInfoRequest()
			if !ok {
				var empty s00.UECapabilityInfoRequest
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-UECapabilityInfoRequest: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldEncode(&sealed) = func(value s00.UECapabilityInfoRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(275), rowUECapabilityInfoRequest: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldCapture(&sealed) = func(v s00.UECapabilityInfoRequest, options aper.DecodeState) (s00.UECapabilityInfoRequest, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUECapabilityInfoRequest(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldCompare(&sealed) = func(v s00.UECapabilityInfoRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUECapabilityInfoRequest(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUECapabilityInfoRequestValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UECapabilityInfoRequest"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UECapabilityInfoRequest) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(275), rowUECapabilityInfoRequest: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.UECapabilityInfoRequest, bool) {
			return value.AsUECapabilityInfoRequest()
		}}
}
func (DownlinkNASTransportIETable) infoEndIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(280), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EndIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-EndIndication"}}}
}
func (t DownlinkNASTransportIETable) EndIndication() DownlinkNASTransportEndIndicationIEBinding {
	return DownlinkNASTransportEndIndicationIEBinding{info: t.infoEndIndication(), codec: func() s00.EndIndicationValueCodec {
		sealed := s00.EndIndicationValueCodec{}
		*s00.BridgeEndIndicationValueCodecFieldPath(&sealed) = "EndIndication"
		*s00.BridgeEndIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EndIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EndIndication
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(280), raw)
			if err != nil {
				var empty s00.EndIndication
				return empty, err
			}
			value, ok := decoded.AsEndIndication()
			if !ok {
				var empty s00.EndIndication
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-EndIndication: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEndIndicationValueCodecFieldEncode(&sealed) = func(value s00.EndIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(280), rowEndIndication: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEndIndicationValueCodecFieldCapture(&sealed) = func(v s00.EndIndication, options aper.DecodeState) (s00.EndIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEndIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEndIndicationValueCodecFieldCompare(&sealed) = func(v s00.EndIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEndIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeEndIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EndIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EndIndication) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(280), rowEndIndication: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.EndIndication, bool) { return value.AsEndIndication() }}
}
func (DownlinkNASTransportIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-PendingDataIndication"}}}
}
func (t DownlinkNASTransportIETable) PendingDataIndication() DownlinkNASTransportPendingDataIndicationIEBinding {
	return DownlinkNASTransportPendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.PendingDataIndication) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (DownlinkNASTransportIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}
func (t DownlinkNASTransportIETable) SubscriptionBasedUEDifferentiationInfo() DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding {
	return DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: func() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
		sealed := s31.SubscriptionBasedUEDifferentiationInfoValueCodec{}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s30.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s30.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s30.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s30.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
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
		inject: func(value s30.SubscriptionBasedUEDifferentiationInfo) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}}
}
func (DownlinkNASTransportIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}
func (t DownlinkNASTransportIETable) AdditionalRRMPriorityIndex() DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding {
	return DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AdditionalRRMPriorityIndex) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (DownlinkNASTransportIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-UERadioCapabilityID"}}}
}
func (t DownlinkNASTransportIETable) UERadioCapabilityID() DownlinkNASTransportUERadioCapabilityIDIEBinding {
	return DownlinkNASTransportUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.UERadioCapabilityID) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (DownlinkNASTransportIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-Masked-IMEISV"}}}
}
func (t DownlinkNASTransportIETable) MaskedIMEISV() DownlinkNASTransportMaskedIMEISVIEBinding {
	return DownlinkNASTransportMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MaskedIMEISV) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.MaskedIMEISV, bool) { return value.AsMaskedIMEISV() }}
}
func (DownlinkNASTransportIETable) infoCoarseUELocation() s00.FieldInfo {
	return s00.FieldInfo{Table: DownlinkNASTransportIEs().ID(), ID: s00.ProtocolIEID(354), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "DownlinkNASTransport-IEs", Row: "id-CoarseUELocation"}}}
}
func (t DownlinkNASTransportIETable) CoarseUELocation() DownlinkNASTransportCoarseUELocationIEBinding {
	return DownlinkNASTransportCoarseUELocationIEBinding{info: t.infoCoarseUELocation(), codec: func() s00.CoarseUELocationValueCodec {
		sealed := s00.CoarseUELocationValueCodec{}
		*s00.BridgeCoarseUELocationValueCodecFieldPath(&sealed) = "CoarseUELocation"
		*s00.BridgeCoarseUELocationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, err
			}
			var zero DownlinkNASTransportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(354), raw)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, err
			}
			value, ok := decoded.AsCoarseUELocation()
			if !ok {
				var empty s00.CoarseUELocation
				return empty, fmt.Errorf("binding DownlinkNASTransport-IEs.id-CoarseUELocation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCoarseUELocationValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (DownlinkNASTransportIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CoarseUELocation) DownlinkNASTransportIEValue {
			return DownlinkNASTransportIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}
		}, get: func(value *DownlinkNASTransportIEValue) (*s00.CoarseUELocation, bool) {
			return value.AsCoarseUELocation()
		}}
}
func (t DownlinkNASTransportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (DownlinkNASTransportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(26):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-NAS-PDU requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(106):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-SubscriberProfileIDforRFP requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(249):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-DLNASPDUDeliveryAckRequest requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(275):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-UECapabilityInfoRequest requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(280):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-EndIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(354):
		return DownlinkNASTransportIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return DownlinkNASTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return DownlinkNASTransportIEField{}, aper.OperationError(err, "Opaque")
		}
		return DownlinkNASTransportIEField{Id: id, Criticality: criticality, Value: DownlinkNASTransportIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type PWSFailureIndicationIETable struct{}

func PWSFailureIndicationIEs() PWSFailureIndicationIETable { return PWSFailureIndicationIETable{} }
func (PWSFailureIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSFailureIndicationIEs"}
		return sealed
	}()
}
func (PWSFailureIndicationIETable) Table() s00.PWSFailureIndicationIEValueIETable {
	return func() s00.PWSFailureIndicationIEValueIETable {
		sealed := s00.PWSFailureIndicationIEValueIETable{}
		*s00.BridgePWSFailureIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PWSFailureIndicationIETable) infoPWSfailedECGIList() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(222), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PWSfailedECGIList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSFailureIndicationIEs", Row: "id-PWSfailedECGIList"}}}
}
func (t PWSFailureIndicationIETable) PWSfailedECGIList() PWSFailureIndicationPWSfailedECGIListIEBinding {
	return PWSFailureIndicationPWSfailedECGIListIEBinding{info: t.infoPWSfailedECGIList(), codec: func() s20.PWSfailedECGIListValueCodec {
		sealed := s20.PWSfailedECGIListValueCodec{}
		*s20.BridgePWSfailedECGIListValueCodecFieldPath(&sealed) = "PWSfailedECGIList"
		*s20.BridgePWSfailedECGIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PWSfailedECGIList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.PWSfailedECGIList
				return empty, err
			}
			var zero PWSFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(222), raw)
			if err != nil {
				var empty s20.PWSfailedECGIList
				return empty, err
			}
			value, ok := decoded.AsPWSfailedECGIList()
			if !ok {
				var empty s20.PWSfailedECGIList
				return empty, fmt.Errorf("binding PWSFailureIndicationIEs.id-PWSfailedECGIList: no selected value")
			}
			return *value, nil
		}
		*s20.BridgePWSfailedECGIListValueCodecFieldEncode(&sealed) = func(value s20.PWSfailedECGIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSFailureIndicationIEValue{id: s00.ProtocolIEID(222), rowPWSfailedECGIList: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgePWSfailedECGIListValueCodecFieldCapture(&sealed) = func(v s20.PWSfailedECGIList, options aper.DecodeState) (s20.PWSfailedECGIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APPWSfailedECGIList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s20.BridgePWSfailedECGIListValueCodecFieldCompare(&sealed) = func(v s20.PWSfailedECGIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APPWSfailedECGIList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgePWSfailedECGIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PWSfailedECGIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.PWSfailedECGIList) PWSFailureIndicationIEValue {
			return PWSFailureIndicationIEValue{id: s00.ProtocolIEID(222), rowPWSfailedECGIList: &value}
		}, get: func(value *PWSFailureIndicationIEValue) (*s20.PWSfailedECGIList, bool) {
			return value.AsPWSfailedECGIList()
		}}
}
func (PWSFailureIndicationIETable) infoGlobalENBID() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(59), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-ENB-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSFailureIndicationIEs", Row: "id-Global-ENB-ID"}}}
}
func (t PWSFailureIndicationIETable) GlobalENBID() PWSFailureIndicationGlobalENBIDIEBinding {
	return PWSFailureIndicationGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s18.GlobalENBIDValueCodec {
		sealed := s18.GlobalENBIDValueCodec{}
		*s18.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s18.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, err
			}
			var zero PWSFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, err
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s18.GlobalENBID
				return empty, fmt.Errorf("binding PWSFailureIndicationIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s18.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSFailureIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGlobalENBIDValueCodecFieldCapture(&sealed) = func(v s18.GlobalENBID, options aper.DecodeState) (s18.GlobalENBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APGlobalENBID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGlobalENBIDValueCodecFieldCompare(&sealed) = func(v s18.GlobalENBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APGlobalENBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s18.BridgeGlobalENBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalENBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GlobalENBID) PWSFailureIndicationIEValue {
			return PWSFailureIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *PWSFailureIndicationIEValue) (*s18.GlobalENBID, bool) { return value.AsGlobalENBID() }}
}
func (t PWSFailureIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PWSFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(222):
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-PWSfailedECGIList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(59):
		return PWSFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Global-ENB-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PWSFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PWSFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return PWSFailureIndicationIEField{Id: id, Criticality: criticality, Value: PWSFailureIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type UEContextReleaseRequestIETable struct{}

func UEContextReleaseRequestIEs() UEContextReleaseRequestIETable {
	return UEContextReleaseRequestIETable{}
}
func (UEContextReleaseRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs"}
		return sealed
	}()
}
func (UEContextReleaseRequestIETable) Table() s00.UEContextReleaseRequestIEValueIETable {
	return func() s00.UEContextReleaseRequestIEValueIETable {
		sealed := s00.UEContextReleaseRequestIEValueIETable{}
		*s00.BridgeUEContextReleaseRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextReleaseRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs", Row: "id-MME-UE-S1AP-ID"}}}
}
func (t UEContextReleaseRequestIETable) MMEUES1APID() UEContextReleaseRequestMMEUES1APIDIEBinding {
	return UEContextReleaseRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			var zero UEContextReleaseRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding UEContextReleaseRequest-IEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MMEUES1APID) UEContextReleaseRequestIEValue {
			return UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *UEContextReleaseRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (UEContextReleaseRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs", Row: "id-eNB-UE-S1AP-ID"}}}
}
func (t UEContextReleaseRequestIETable) ENBUES1APID() UEContextReleaseRequestENBUES1APIDIEBinding {
	return UEContextReleaseRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero UEContextReleaseRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding UEContextReleaseRequest-IEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) UEContextReleaseRequestIEValue {
			return UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *UEContextReleaseRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (UEContextReleaseRequestIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseRequestIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs", Row: "id-Cause"}}}
}
func (t UEContextReleaseRequestIETable) Cause() UEContextReleaseRequestCauseIEBinding {
	return UEContextReleaseRequestCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			var zero UEContextReleaseRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding UEContextReleaseRequest-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) UEContextReleaseRequestIEValue {
			return UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextReleaseRequestIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (UEContextReleaseRequestIETable) infoGWContextReleaseIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseRequestIEs().ID(), ID: s00.ProtocolIEID(164), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GWContextReleaseIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs", Row: "id-GWContextReleaseIndication"}}}
}
func (t UEContextReleaseRequestIETable) GWContextReleaseIndication() UEContextReleaseRequestGWContextReleaseIndicationIEBinding {
	return UEContextReleaseRequestGWContextReleaseIndicationIEBinding{info: t.infoGWContextReleaseIndication(), codec: func() s00.GWContextReleaseIndicationValueCodec {
		sealed := s00.GWContextReleaseIndicationValueCodec{}
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldPath(&sealed) = "GWContextReleaseIndication"
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GWContextReleaseIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.GWContextReleaseIndication
				return empty, err
			}
			var zero UEContextReleaseRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(164), raw)
			if err != nil {
				var empty s00.GWContextReleaseIndication
				return empty, err
			}
			value, ok := decoded.AsGWContextReleaseIndication()
			if !ok {
				var empty s00.GWContextReleaseIndication
				return empty, fmt.Errorf("binding UEContextReleaseRequest-IEs.id-GWContextReleaseIndication: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldEncode(&sealed) = func(value s00.GWContextReleaseIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(164), rowGWContextReleaseIndication: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldCapture(&sealed) = func(v s00.GWContextReleaseIndication, options aper.DecodeState) (s00.GWContextReleaseIndication, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APGWContextReleaseIndication(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldCompare(&sealed) = func(v s00.GWContextReleaseIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APGWContextReleaseIndication(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeGWContextReleaseIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GWContextReleaseIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.GWContextReleaseIndication) UEContextReleaseRequestIEValue {
			return UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(164), rowGWContextReleaseIndication: &value}
		}, get: func(value *UEContextReleaseRequestIEValue) (*s00.GWContextReleaseIndication, bool) {
			return value.AsGWContextReleaseIndication()
		}}
}
func (UEContextReleaseRequestIETable) infoSecondaryRATDataUsageReportList() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseRequestIEs().ID(), ID: s00.ProtocolIEID(264), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecondaryRATDataUsageReportList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseRequest-IEs", Row: "id-SecondaryRATDataUsageReportList"}}}
}
func (t UEContextReleaseRequestIETable) SecondaryRATDataUsageReportList() UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding {
	return UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding{info: t.infoSecondaryRATDataUsageReportList(), codec: func() s28.SecondaryRATDataUsageReportListValueCodec {
		sealed := s28.SecondaryRATDataUsageReportListValueCodec{}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldPath(&sealed) = "SecondaryRATDataUsageReportList"
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			var zero UEContextReleaseRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(264), raw)
			if err != nil {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, err
			}
			value, ok := decoded.AsSecondaryRATDataUsageReportList()
			if !ok {
				var empty s28.SecondaryRATDataUsageReportList
				return empty, fmt.Errorf("binding UEContextReleaseRequest-IEs.id-SecondaryRATDataUsageReportList: no selected value")
			}
			return *value, nil
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&sealed) = func(value s28.SecondaryRATDataUsageReportList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}).encodeFresh(fresh, budget)
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCapture(&sealed) = func(v s28.SecondaryRATDataUsageReportList, options aper.DecodeState) (s28.SecondaryRATDataUsageReportList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s28.BridgeCaptureS1APSecondaryRATDataUsageReportList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldCompare(&sealed) = func(v s28.SecondaryRATDataUsageReportList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s28.BridgeCompareS1APSecondaryRATDataUsageReportList(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecondaryRATDataUsageReportList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s28.SecondaryRATDataUsageReportList) UEContextReleaseRequestIEValue {
			return UEContextReleaseRequestIEValue{id: s00.ProtocolIEID(264), rowSecondaryRATDataUsageReportList: &value}
		}, get: func(value *UEContextReleaseRequestIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
			return value.AsSecondaryRATDataUsageReportList()
		}}
}
func (t UEContextReleaseRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextReleaseRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(164):
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-GWContextReleaseIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(264):
		return UEContextReleaseRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecondaryRATDataUsageReportList requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextReleaseRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextReleaseRequestIEField{Id: id, Criticality: criticality, Value: UEContextReleaseRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CNTypeRestrictionsCodec binds the complete APER value type.
func CNTypeRestrictionsCodec() s14.CNTypeRestrictionsValueCodec {
	return HandoverRestrictionListExtIEs().CNTypeRestrictions().Codec()
}

// DLNASPDUDeliveryAckRequestCodec binds the complete APER value type.
func DLNASPDUDeliveryAckRequestCodec() s00.DLNASPDUDeliveryAckRequestValueCodec {
	return DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Codec()
}

// GWContextReleaseIndicationCodec binds the complete APER value type.
func GWContextReleaseIndicationCodec() s00.GWContextReleaseIndicationValueCodec {
	return UEContextReleaseRequestIEs().GWContextReleaseIndication().Codec()
}

// GlobalENBIDCodec binds the complete APER value type.
func GlobalENBIDCodec() s18.GlobalENBIDValueCodec {
	return PWSFailureIndicationIEs().GlobalENBID().Codec()
}

// HandoverRestrictionListCodec binds the complete APER value type.
func HandoverRestrictionListCodec() HandoverRestrictionListValueCodec {
	return DownlinkNASTransportIEs().HandoverRestrictionList().Codec()
}

// NASPDUCodec binds the complete APER value type.
func NASPDUCodec() s01.NASPDUValueCodec { return DownlinkNASTransportIEs().NASPDU().Codec() }

// NRUESecurityCapabilitiesCodec binds the complete APER value type.
func NRUESecurityCapabilitiesCodec() s19.NRUESecurityCapabilitiesValueCodec {
	return DownlinkNASTransportIEs().NRUESecurityCapabilities().Codec()
}

// NRrestrictionin5GSCodec binds the complete APER value type.
func NRrestrictionin5GSCodec() s01.NRrestrictionin5GSValueCodec {
	return HandoverRestrictionListExtIEs().NRrestrictionin5GS().Codec()
}

// NRrestrictioninEPSasSecondaryRATCodec binds the complete APER value type.
func NRrestrictioninEPSasSecondaryRATCodec() s01.NRrestrictioninEPSasSecondaryRATValueCodec {
	return HandoverRestrictionListExtIEs().NRrestrictioninEPSasSecondaryRAT().Codec()
}

// NotificationCellListCodec binds the complete source value type.
func NotificationCellListCodec() s19.NotificationCellListValueCodec {
	return func() s19.NotificationCellListValueCodec {
		sealed := s19.NotificationCellListValueCodec{}
		*s19.BridgeNotificationCellListValueCodecFieldPath(&sealed) = "NotificationCellList"
		*s19.BridgeNotificationCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NotificationCellList, error) {
			var complete NotificationCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s19.NotificationCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s19.BridgeNotificationCellListValueCodecFieldEncode(&sealed) = func(value s19.NotificationCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := NotificationCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s19.BridgeNotificationCellListValueCodecFieldCapture(&sealed) = func(v s19.NotificationCellList, options aper.DecodeState) (s19.NotificationCellList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APNotificationCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeNotificationCellListValueCodecFieldCompare(&sealed) = func(v s19.NotificationCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APNotificationCellList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNotificationCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NotificationCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PC5QoSFlowListCodec binds the complete source value type.
func PC5QoSFlowListCodec() s20.PC5QoSFlowListValueCodec {
	return func() s20.PC5QoSFlowListValueCodec {
		sealed := s20.PC5QoSFlowListValueCodec{}
		*s20.BridgePC5QoSFlowListValueCodecFieldPath(&sealed) = "PC5QoSFlowList"
		*s20.BridgePC5QoSFlowListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.PC5QoSFlowList, error) {
			var complete PC5QoSFlowListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.PC5QoSFlowList
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgePC5QoSFlowListValueCodecFieldEncode(&sealed) = func(value s20.PC5QoSFlowList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := PC5QoSFlowListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgePC5QoSFlowListValueCodecFieldCapture(&sealed) = func(v s20.PC5QoSFlowList, options aper.DecodeState) (s20.PC5QoSFlowList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APPC5QoSFlowList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgePC5QoSFlowListValueCodecFieldCompare(&sealed) = func(v s20.PC5QoSFlowList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APPC5QoSFlowList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgePC5QoSFlowListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSFlowList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PLMNListforQMCCodec binds the complete source value type.
func PLMNListforQMCCodec() s01.PLMNListforQMCValueCodec {
	return func() s01.PLMNListforQMCValueCodec {
		sealed := s01.PLMNListforQMCValueCodec{}
		*s01.BridgePLMNListforQMCValueCodecFieldPath(&sealed) = "PLMNListforQMC"
		*s01.BridgePLMNListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PLMNListforQMC, error) {
			var complete PLMNListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.PLMNListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgePLMNListforQMCValueCodecFieldEncode(&sealed) = func(value s00.PLMNListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := PLMNListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgePLMNListforQMCValueCodecFieldCapture(&sealed) = func(v s00.PLMNListforQMC, options aper.DecodeState) (s00.PLMNListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPLMNListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePLMNListforQMCValueCodecFieldCompare(&sealed) = func(v s00.PLMNListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APPLMNListforQMC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePLMNListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PLMNListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PLMNidentityCodec binds the complete APER value type.
func PLMNidentityCodec() s01.PLMNidentityValueCodec {
	return HandoverRestrictionListExtIEs().LastNGRANPLMNIdentity().Codec()
}

// PWSfailedECGIListCodec binds the complete APER value type.
func PWSfailedECGIListCodec() s20.PWSfailedECGIListValueCodec {
	return PWSFailureIndicationIEs().PWSfailedECGIList().Codec()
}

// PendingDataIndicationCodec binds the complete APER value type.
func PendingDataIndicationCodec() s01.PendingDataIndicationValueCodec {
	return DownlinkNASTransportIEs().PendingDataIndication().Codec()
}

// RATRestrictionsCodec binds the complete APER value type.
func RATRestrictionsCodec() s20.RATRestrictionsValueCodec {
	return HandoverRestrictionListExtIEs().RATRestrictions().Codec()
}

// RecommendedCellListCodec binds the complete source value type.
func RecommendedCellListCodec() s26.RecommendedCellListValueCodec {
	return func() s26.RecommendedCellListValueCodec {
		sealed := s26.RecommendedCellListValueCodec{}
		*s26.BridgeRecommendedCellListValueCodecFieldPath(&sealed) = "RecommendedCellList"
		*s26.BridgeRecommendedCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.RecommendedCellList, error) {
			var complete RecommendedCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s26.RecommendedCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s26.BridgeRecommendedCellListValueCodecFieldEncode(&sealed) = func(value s26.RecommendedCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := RecommendedCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s26.BridgeRecommendedCellListValueCodecFieldCapture(&sealed) = func(v s26.RecommendedCellList, options aper.DecodeState) (s26.RecommendedCellList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s26.BridgeCaptureS1APRecommendedCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeRecommendedCellListValueCodecFieldCompare(&sealed) = func(v s26.RecommendedCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APRecommendedCellList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s26.BridgeRecommendedCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RecommendedCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RecommendedENBListCodec binds the complete source value type.
func RecommendedENBListCodec() s32.RecommendedENBListValueCodec {
	return func() s32.RecommendedENBListValueCodec {
		sealed := s32.RecommendedENBListValueCodec{}
		*s32.BridgeRecommendedENBListValueCodecFieldPath(&sealed) = "RecommendedENBList"
		*s32.BridgeRecommendedENBListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBList, error) {
			var complete RecommendedENBListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.RecommendedENBList
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeRecommendedENBListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := RecommendedENBListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeRecommendedENBListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBList, options aper.DecodeState) (s32.RecommendedENBList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s33.BridgeCaptureS1APRecommendedENBList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s32.BridgeRecommendedENBListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s33.BridgeCompareS1APRecommendedENBList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RecommendedENBList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ReportingCellListCodec binds the complete source value type.
func ReportingCellListCodec() s20.ReportingCellListValueCodec {
	return func() s20.ReportingCellListValueCodec {
		sealed := s20.ReportingCellListValueCodec{}
		*s20.BridgeReportingCellListValueCodecFieldPath(&sealed) = "ReportingCellList"
		*s20.BridgeReportingCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ReportingCellList, error) {
			var complete ReportingCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.ReportingCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeReportingCellListValueCodecFieldEncode(&sealed) = func(value s20.ReportingCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ReportingCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeReportingCellListValueCodecFieldCapture(&sealed) = func(v s20.ReportingCellList, options aper.DecodeState) (s20.ReportingCellList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APReportingCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s20.BridgeReportingCellListValueCodecFieldCompare(&sealed) = func(v s20.ReportingCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APReportingCellList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeReportingCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportingCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// RequestedCellListCodec binds the complete source value type.
func RequestedCellListCodec() s20.RequestedCellListValueCodec {
	return func() s20.RequestedCellListValueCodec {
		sealed := s20.RequestedCellListValueCodec{}
		*s20.BridgeRequestedCellListValueCodecFieldPath(&sealed) = "RequestedCellList"
		*s20.BridgeRequestedCellListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.RequestedCellList, error) {
			var complete RequestedCellListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s20.RequestedCellList
				return zero, err
			}
			return complete.Value, nil
		}
		*s20.BridgeRequestedCellListValueCodecFieldEncode(&sealed) = func(value s20.RequestedCellList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := RequestedCellListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s20.BridgeRequestedCellListValueCodecFieldCapture(&sealed) = func(v s20.RequestedCellList, options aper.DecodeState) (s20.RequestedCellList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APRequestedCellList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s20.BridgeRequestedCellListValueCodecFieldCompare(&sealed) = func(v s20.RequestedCellList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APRequestedCellList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeRequestedCellListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestedCellList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SRVCCOperationPossibleCodec binds the complete APER value type.
func SRVCCOperationPossibleCodec() s01.SRVCCOperationPossibleValueCodec {
	return DownlinkNASTransportIEs().SRVCCOperationPossible().Codec()
}

// SensorMeasConfigNameListCodec binds the complete source value type.
func SensorMeasConfigNameListCodec() s30.SensorMeasConfigNameListValueCodec {
	return func() s30.SensorMeasConfigNameListValueCodec {
		sealed := s30.SensorMeasConfigNameListValueCodec{}
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldPath(&sealed) = "SensorMeasConfigNameList"
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SensorMeasConfigNameList, error) {
			var complete SensorMeasConfigNameListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s30.SensorMeasConfigNameList
				return zero, err
			}
			return complete.Value, nil
		}
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldEncode(&sealed) = func(value s30.SensorMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := SensorMeasConfigNameListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldCapture(&sealed) = func(v s30.SensorMeasConfigNameList, options aper.DecodeState) (s30.SensorMeasConfigNameList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSensorMeasConfigNameList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldCompare(&sealed) = func(v s30.SensorMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSensorMeasConfigNameList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeSensorMeasConfigNameListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SensorMeasConfigNameList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SubscriberProfileIDforRFPCodec binds the complete APER value type.
func SubscriberProfileIDforRFPCodec() s01.SubscriberProfileIDforRFPValueCodec {
	return DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Codec()
}

// UECapabilityInfoRequestCodec binds the complete APER value type.
func UECapabilityInfoRequestCodec() s02.UECapabilityInfoRequestValueCodec {
	return DownlinkNASTransportIEs().UECapabilityInfoRequest().Codec()
}

// UnlicensedSpectrumRestrictionCodec binds the complete APER value type.
func UnlicensedSpectrumRestrictionCodec() s02.UnlicensedSpectrumRestrictionValueCodec {
	return HandoverRestrictionListExtIEs().UnlicensedSpectrumRestriction().Codec()
}
func BridgeDownlinkNASTransportAPERValueFieldContext(v *DownlinkNASTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportAPERValueFieldReceived(v *DownlinkNASTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportAPERValueFieldReplay(v *DownlinkNASTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportAPERValueFieldWithoutReplay(v *DownlinkNASTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportAdditionalRRMPriorityIndexIEBindingFieldCodec(v *DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportAdditionalRRMPriorityIndexIEBindingFieldGet(v *DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportAdditionalRRMPriorityIndexIEBindingFieldInfo(v *DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportAdditionalRRMPriorityIndexIEBindingFieldInject(v *DownlinkNASTransportAdditionalRRMPriorityIndexIEBinding) *func(s00.AdditionalRRMPriorityIndex) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportCEModeBRestrictedIEBindingFieldCodec(v *DownlinkNASTransportCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportCEModeBRestrictedIEBindingFieldGet(v *DownlinkNASTransportCEModeBRestrictedIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportCEModeBRestrictedIEBindingFieldInfo(v *DownlinkNASTransportCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportCEModeBRestrictedIEBindingFieldInject(v *DownlinkNASTransportCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportCoarseUELocationIEBindingFieldCodec(v *DownlinkNASTransportCoarseUELocationIEBinding) *s00.CoarseUELocationValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportCoarseUELocationIEBindingFieldGet(v *DownlinkNASTransportCoarseUELocationIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.CoarseUELocation, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportCoarseUELocationIEBindingFieldInfo(v *DownlinkNASTransportCoarseUELocationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportCoarseUELocationIEBindingFieldInject(v *DownlinkNASTransportCoarseUELocationIEBinding) *func(s00.CoarseUELocation) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportDLNASPDUDeliveryAckRequestIEBindingFieldCodec(v *DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) *s00.DLNASPDUDeliveryAckRequestValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportDLNASPDUDeliveryAckRequestIEBindingFieldGet(v *DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.DLNASPDUDeliveryAckRequest, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportDLNASPDUDeliveryAckRequestIEBindingFieldInfo(v *DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportDLNASPDUDeliveryAckRequestIEBindingFieldInject(v *DownlinkNASTransportDLNASPDUDeliveryAckRequestIEBinding) *func(s00.DLNASPDUDeliveryAckRequest) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportENBUES1APIDIEBindingFieldCodec(v *DownlinkNASTransportENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportENBUES1APIDIEBindingFieldGet(v *DownlinkNASTransportENBUES1APIDIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportENBUES1APIDIEBindingFieldInfo(v *DownlinkNASTransportENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportENBUES1APIDIEBindingFieldInject(v *DownlinkNASTransportENBUES1APIDIEBinding) *func(s00.ENBUES1APID) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportEndIndicationIEBindingFieldCodec(v *DownlinkNASTransportEndIndicationIEBinding) *s00.EndIndicationValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportEndIndicationIEBindingFieldGet(v *DownlinkNASTransportEndIndicationIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.EndIndication, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportEndIndicationIEBindingFieldInfo(v *DownlinkNASTransportEndIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportEndIndicationIEBindingFieldInject(v *DownlinkNASTransportEndIndicationIEBinding) *func(s00.EndIndication) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportEnhancedCoverageRestrictedIEBindingFieldCodec(v *DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportEnhancedCoverageRestrictedIEBindingFieldGet(v *DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportEnhancedCoverageRestrictedIEBindingFieldInfo(v *DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportEnhancedCoverageRestrictedIEBindingFieldInject(v *DownlinkNASTransportEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportFieldExtCount(v *DownlinkNASTransport) *int64   { return &v.extCount }
func BridgeDownlinkNASTransportFieldExtData(v *DownlinkNASTransport) *[][]byte { return &v.extData }
func BridgeDownlinkNASTransportFieldExtOrigin(v *DownlinkNASTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeDownlinkNASTransportFieldExtPresent(v *DownlinkNASTransport) *[]bool { return &v.extPresent }
func BridgeDownlinkNASTransportFieldExtWire(v *DownlinkNASTransport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeDownlinkNASTransportFieldPerExtPadding(v *DownlinkNASTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeDownlinkNASTransportFieldPerPadding(v *DownlinkNASTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeDownlinkNASTransportFieldProtocolIEsIndef(v *DownlinkNASTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeDownlinkNASTransportFieldReceived(v *DownlinkNASTransport) *bool { return &v.received }
func BridgeDownlinkNASTransportFieldReceivedAbsolute(v *DownlinkNASTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeDownlinkNASTransportFieldReceivedBytes(v *DownlinkNASTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeDownlinkNASTransportFieldReceivedLocation(v *DownlinkNASTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeDownlinkNASTransportFieldReplay(v *DownlinkNASTransport) *aper.Snapshot { return &v.replay }
func BridgeDownlinkNASTransportFieldStream(v *DownlinkNASTransport) *aper.WireSpan { return &v.stream }
func BridgeDownlinkNASTransportFieldWithoutReplay(v *DownlinkNASTransport) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportHandoverRestrictionListIEBindingFieldCodec(v *DownlinkNASTransportHandoverRestrictionListIEBinding) *HandoverRestrictionListValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportHandoverRestrictionListIEBindingFieldGet(v *DownlinkNASTransportHandoverRestrictionListIEBinding) *func(*DownlinkNASTransportIEValue) (*HandoverRestrictionList, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportHandoverRestrictionListIEBindingFieldInfo(v *DownlinkNASTransportHandoverRestrictionListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportHandoverRestrictionListIEBindingFieldInject(v *DownlinkNASTransportHandoverRestrictionListIEBinding) *func(HandoverRestrictionList) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportIEContainerAPERValueFieldContext(v *DownlinkNASTransportIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEContainerAPERValueFieldReceived(v *DownlinkNASTransportIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEContainerAPERValueFieldReplay(v *DownlinkNASTransportIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEContainerAPERValueFieldWithoutReplay(v *DownlinkNASTransportIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldCapture(v *DownlinkNASTransportIEContainerValueCodec) *func(DownlinkNASTransportIEContainer, aper.DecodeState) (DownlinkNASTransportIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldCompare(v *DownlinkNASTransportIEContainerValueCodec) *func(DownlinkNASTransportIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldContext(v *DownlinkNASTransportIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldDecode(v *DownlinkNASTransportIEContainerValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransportIEContainer, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldEncode(v *DownlinkNASTransportIEContainerValueCodec) *func(DownlinkNASTransportIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportIEContainerValueCodecFieldPath(v *DownlinkNASTransportIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportIEContainerValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportIEContainerValueCodec, a0 DownlinkNASTransportIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportIEContainerValueCodecMethodEncodeChanged(v DownlinkNASTransportIEContainerValueCodec, a0 DownlinkNASTransportIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNASTransportIEFieldAPERValueFieldContext(v *DownlinkNASTransportIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEFieldAPERValueFieldReceived(v *DownlinkNASTransportIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEFieldAPERValueFieldReplay(v *DownlinkNASTransportIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEFieldAPERValueFieldWithoutReplay(v *DownlinkNASTransportIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEFieldFieldReceived(v *DownlinkNASTransportIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeDownlinkNASTransportIEFieldFieldReplay(v *DownlinkNASTransportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEFieldFieldStream(v *DownlinkNASTransportIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeDownlinkNASTransportIEFieldFieldWithoutReplay(v *DownlinkNASTransportIEField) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEFieldMethodMarshalAPERTo(v *DownlinkNASTransportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkNASTransportIEFieldMethodUnmarshalAPERFrom(v *DownlinkNASTransportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldCapture(v *DownlinkNASTransportIEFieldValueCodec) *func(DownlinkNASTransportIEField, aper.DecodeState) (DownlinkNASTransportIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldCompare(v *DownlinkNASTransportIEFieldValueCodec) *func(DownlinkNASTransportIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldContext(v *DownlinkNASTransportIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldDecode(v *DownlinkNASTransportIEFieldValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransportIEField, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldEncode(v *DownlinkNASTransportIEFieldValueCodec) *func(DownlinkNASTransportIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportIEFieldValueCodecFieldPath(v *DownlinkNASTransportIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportIEFieldValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportIEFieldValueCodec, a0 DownlinkNASTransportIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportIEFieldValueCodecMethodEncodeChanged(v DownlinkNASTransportIEFieldValueCodec, a0 DownlinkNASTransportIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNASTransportIETableMethodInfoAdditionalRRMPriorityIndex(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeDownlinkNASTransportIETableMethodInfoCEModeBRestricted(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgeDownlinkNASTransportIETableMethodInfoCoarseUELocation(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoCoarseUELocation()
}
func BridgeDownlinkNASTransportIETableMethodInfoDLNASPDUDeliveryAckRequest(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoDLNASPDUDeliveryAckRequest()
}
func BridgeDownlinkNASTransportIETableMethodInfoENBUES1APID(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeDownlinkNASTransportIETableMethodInfoEndIndication(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoEndIndication()
}
func BridgeDownlinkNASTransportIETableMethodInfoEnhancedCoverageRestricted(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgeDownlinkNASTransportIETableMethodInfoHandoverRestrictionList(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoHandoverRestrictionList()
}
func BridgeDownlinkNASTransportIETableMethodInfoMMEUES1APID(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeDownlinkNASTransportIETableMethodInfoMaskedIMEISV(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeDownlinkNASTransportIETableMethodInfoNASPDU(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoNASPDU()
}
func BridgeDownlinkNASTransportIETableMethodInfoNRUESecurityCapabilities(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgeDownlinkNASTransportIETableMethodInfoPendingDataIndication(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgeDownlinkNASTransportIETableMethodInfoSRVCCOperationPossible(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoSRVCCOperationPossible()
}
func BridgeDownlinkNASTransportIETableMethodInfoSubscriberProfileIDforRFP(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoSubscriberProfileIDforRFP()
}
func BridgeDownlinkNASTransportIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeDownlinkNASTransportIETableMethodInfoUECapabilityInfoRequest(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoUECapabilityInfoRequest()
}
func BridgeDownlinkNASTransportIETableMethodInfoUERadioCapability(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeDownlinkNASTransportIETableMethodInfoUERadioCapabilityID(v DownlinkNASTransportIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListAPERValueFieldContext(v *DownlinkNASTransportIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListAPERValueFieldReceived(v *DownlinkNASTransportIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListAPERValueFieldReplay(v *DownlinkNASTransportIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *DownlinkNASTransportIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldCapture(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNASTransportIEValueERABIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldCompare(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNASTransportIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldContext(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldDecode(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldEncode(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *func(DownlinkNASTransportIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecFieldPath(v *DownlinkNASTransportIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportIEValueERABIEContainerListValueCodec, a0 DownlinkNASTransportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportIEValueERABIEContainerListValueCodecMethodEncodeChanged(v DownlinkNASTransportIEValueERABIEContainerListValueCodec, a0 DownlinkNASTransportIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNASTransportIEValueFieldId(v *DownlinkNASTransportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeDownlinkNASTransportIEValueFieldIsOpaque(v *DownlinkNASTransportIEValue) *bool {
	return &v.isOpaque
}
func BridgeDownlinkNASTransportIEValueFieldOpaque(v *DownlinkNASTransportIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeDownlinkNASTransportIEValueFieldReceived(v *DownlinkNASTransportIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEValueFieldReplay(v *DownlinkNASTransportIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEValueFieldRowAdditionalRRMPriorityIndex(v *DownlinkNASTransportIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeDownlinkNASTransportIEValueFieldRowCEModeBRestricted(v *DownlinkNASTransportIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgeDownlinkNASTransportIEValueFieldRowCoarseUELocation(v *DownlinkNASTransportIEValue) **s00.CoarseUELocation {
	return &v.rowCoarseUELocation
}
func BridgeDownlinkNASTransportIEValueFieldRowDLNASPDUDeliveryAckRequest(v *DownlinkNASTransportIEValue) **s00.DLNASPDUDeliveryAckRequest {
	return &v.rowDLNASPDUDeliveryAckRequest
}
func BridgeDownlinkNASTransportIEValueFieldRowENBUES1APID(v *DownlinkNASTransportIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeDownlinkNASTransportIEValueFieldRowEndIndication(v *DownlinkNASTransportIEValue) **s00.EndIndication {
	return &v.rowEndIndication
}
func BridgeDownlinkNASTransportIEValueFieldRowEnhancedCoverageRestricted(v *DownlinkNASTransportIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgeDownlinkNASTransportIEValueFieldRowHandoverRestrictionList(v *DownlinkNASTransportIEValue) **HandoverRestrictionList {
	return &v.rowHandoverRestrictionList
}
func BridgeDownlinkNASTransportIEValueFieldRowMMEUES1APID(v *DownlinkNASTransportIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeDownlinkNASTransportIEValueFieldRowMaskedIMEISV(v *DownlinkNASTransportIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeDownlinkNASTransportIEValueFieldRowNASPDU(v *DownlinkNASTransportIEValue) **s00.NASPDU {
	return &v.rowNASPDU
}
func BridgeDownlinkNASTransportIEValueFieldRowNRUESecurityCapabilities(v *DownlinkNASTransportIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgeDownlinkNASTransportIEValueFieldRowPendingDataIndication(v *DownlinkNASTransportIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeDownlinkNASTransportIEValueFieldRowSRVCCOperationPossible(v *DownlinkNASTransportIEValue) **s00.SRVCCOperationPossible {
	return &v.rowSRVCCOperationPossible
}
func BridgeDownlinkNASTransportIEValueFieldRowSubscriberProfileIDforRFP(v *DownlinkNASTransportIEValue) **s00.SubscriberProfileIDforRFP {
	return &v.rowSubscriberProfileIDforRFP
}
func BridgeDownlinkNASTransportIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *DownlinkNASTransportIEValue) **s30.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeDownlinkNASTransportIEValueFieldRowUECapabilityInfoRequest(v *DownlinkNASTransportIEValue) **s00.UECapabilityInfoRequest {
	return &v.rowUECapabilityInfoRequest
}
func BridgeDownlinkNASTransportIEValueFieldRowUERadioCapability(v *DownlinkNASTransportIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeDownlinkNASTransportIEValueFieldRowUERadioCapabilityID(v *DownlinkNASTransportIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeDownlinkNASTransportIEValueMethodCaptureSemantics(v DownlinkNASTransportIEValue, a0 aper.SemanticCapture) DownlinkNASTransportIEValue {
	return v.captureSemantics(a0)
}
func BridgeDownlinkNASTransportIEValueMethodCompareSemantics(v DownlinkNASTransportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeDownlinkNASTransportIEValueMethodDecode(v DownlinkNASTransportIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (DownlinkNASTransportIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeDownlinkNASTransportIEValueMethodEncode(v DownlinkNASTransportIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeDownlinkNASTransportIEValueMethodEncodeFresh(v DownlinkNASTransportIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeDownlinkNASTransportIEValueMethodMatchesID(v DownlinkNASTransportIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeDownlinkNASTransportIEValueMethodReason(v DownlinkNASTransportIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeDownlinkNASTransportIEValueMethodRule(v DownlinkNASTransportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec, a0 DownlinkNASTransportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v DownlinkNASTransportIEValueProtocolErrorIEContainerListValueCodec, a0 DownlinkNASTransportIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListAPERValueFieldContext(v *DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListAPERValueFieldReceived(v *DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListAPERValueFieldReplay(v *DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *DownlinkNASTransportIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCapture(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolIEContainerList, aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCompare(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldContext(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldDecode(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransportIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldEncode(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *func(DownlinkNASTransportIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecFieldPath(v *DownlinkNASTransportIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportIEValueProtocolIEContainerListValueCodec, a0 DownlinkNASTransportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v DownlinkNASTransportIEValueProtocolIEContainerListValueCodec, a0 DownlinkNASTransportIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDownlinkNASTransportMMEUES1APIDIEBindingFieldCodec(v *DownlinkNASTransportMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportMMEUES1APIDIEBindingFieldGet(v *DownlinkNASTransportMMEUES1APIDIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportMMEUES1APIDIEBindingFieldInfo(v *DownlinkNASTransportMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportMMEUES1APIDIEBindingFieldInject(v *DownlinkNASTransportMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportMaskedIMEISVIEBindingFieldCodec(v *DownlinkNASTransportMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportMaskedIMEISVIEBindingFieldGet(v *DownlinkNASTransportMaskedIMEISVIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportMaskedIMEISVIEBindingFieldInfo(v *DownlinkNASTransportMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportMaskedIMEISVIEBindingFieldInject(v *DownlinkNASTransportMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportMethodMarshalAPERBudget(v *DownlinkNASTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeDownlinkNASTransportMethodMarshalAPERBudgetValue(v *DownlinkNASTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeDownlinkNASTransportMethodMarshalAPERChanged(v *DownlinkNASTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeDownlinkNASTransportMethodMarshalAPERChangedValue(v *DownlinkNASTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportMethodMarshalAPERLegacy(v *DownlinkNASTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeDownlinkNASTransportMethodMarshalAPERNewValue(v *DownlinkNASTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeDownlinkNASTransportMethodMarshalAPERPlanned(v *DownlinkNASTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeDownlinkNASTransportMethodMarshalAPERTo(v *DownlinkNASTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeDownlinkNASTransportMethodUnmarshalAPERFrom(v *DownlinkNASTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeDownlinkNASTransportMethodUnmarshalAPERLegacy(v *DownlinkNASTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeDownlinkNASTransportMethodUnmarshalAPERWithOptions(v *DownlinkNASTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeDownlinkNASTransportNASPDUIEBindingFieldCodec(v *DownlinkNASTransportNASPDUIEBinding) *s01.NASPDUValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportNASPDUIEBindingFieldGet(v *DownlinkNASTransportNASPDUIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.NASPDU, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportNASPDUIEBindingFieldInfo(v *DownlinkNASTransportNASPDUIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportNASPDUIEBindingFieldInject(v *DownlinkNASTransportNASPDUIEBinding) *func(s00.NASPDU) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportNRUESecurityCapabilitiesIEBindingFieldCodec(v *DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportNRUESecurityCapabilitiesIEBindingFieldGet(v *DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) *func(*DownlinkNASTransportIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportNRUESecurityCapabilitiesIEBindingFieldInfo(v *DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportNRUESecurityCapabilitiesIEBindingFieldInject(v *DownlinkNASTransportNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportPendingDataIndicationIEBindingFieldCodec(v *DownlinkNASTransportPendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportPendingDataIndicationIEBindingFieldGet(v *DownlinkNASTransportPendingDataIndicationIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportPendingDataIndicationIEBindingFieldInfo(v *DownlinkNASTransportPendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportPendingDataIndicationIEBindingFieldInject(v *DownlinkNASTransportPendingDataIndicationIEBinding) *func(s00.PendingDataIndication) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportSRVCCOperationPossibleIEBindingFieldCodec(v *DownlinkNASTransportSRVCCOperationPossibleIEBinding) *s01.SRVCCOperationPossibleValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportSRVCCOperationPossibleIEBindingFieldGet(v *DownlinkNASTransportSRVCCOperationPossibleIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.SRVCCOperationPossible, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportSRVCCOperationPossibleIEBindingFieldInfo(v *DownlinkNASTransportSRVCCOperationPossibleIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportSRVCCOperationPossibleIEBindingFieldInject(v *DownlinkNASTransportSRVCCOperationPossibleIEBinding) *func(s00.SRVCCOperationPossible) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportSubscriberProfileIDforRFPIEBindingFieldCodec(v *DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) *s01.SubscriberProfileIDforRFPValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportSubscriberProfileIDforRFPIEBindingFieldGet(v *DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportSubscriberProfileIDforRFPIEBindingFieldInfo(v *DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportSubscriberProfileIDforRFPIEBindingFieldInject(v *DownlinkNASTransportSubscriberProfileIDforRFPIEBinding) *func(s00.SubscriberProfileIDforRFP) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) *s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*DownlinkNASTransportIEValue) (*s30.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *DownlinkNASTransportSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s30.SubscriptionBasedUEDifferentiationInfo) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportUECapabilityInfoRequestIEBindingFieldCodec(v *DownlinkNASTransportUECapabilityInfoRequestIEBinding) *s02.UECapabilityInfoRequestValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportUECapabilityInfoRequestIEBindingFieldGet(v *DownlinkNASTransportUECapabilityInfoRequestIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.UECapabilityInfoRequest, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportUECapabilityInfoRequestIEBindingFieldInfo(v *DownlinkNASTransportUECapabilityInfoRequestIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportUECapabilityInfoRequestIEBindingFieldInject(v *DownlinkNASTransportUECapabilityInfoRequestIEBinding) *func(s00.UECapabilityInfoRequest) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportUERadioCapabilityIDIEBindingFieldCodec(v *DownlinkNASTransportUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportUERadioCapabilityIDIEBindingFieldGet(v *DownlinkNASTransportUERadioCapabilityIDIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportUERadioCapabilityIDIEBindingFieldInfo(v *DownlinkNASTransportUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportUERadioCapabilityIDIEBindingFieldInject(v *DownlinkNASTransportUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportUERadioCapabilityIEBindingFieldCodec(v *DownlinkNASTransportUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeDownlinkNASTransportUERadioCapabilityIEBindingFieldGet(v *DownlinkNASTransportUERadioCapabilityIEBinding) *func(*DownlinkNASTransportIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeDownlinkNASTransportUERadioCapabilityIEBindingFieldInfo(v *DownlinkNASTransportUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeDownlinkNASTransportUERadioCapabilityIEBindingFieldInject(v *DownlinkNASTransportUERadioCapabilityIEBinding) *func(s00.UERadioCapability) DownlinkNASTransportIEValue {
	return &v.inject
}
func BridgeDownlinkNASTransportValueCodecFieldCapture(v *DownlinkNASTransportValueCodec) *func(DownlinkNASTransport, aper.DecodeState) (DownlinkNASTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeDownlinkNASTransportValueCodecFieldCompare(v *DownlinkNASTransportValueCodec) *func(DownlinkNASTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeDownlinkNASTransportValueCodecFieldContext(v *DownlinkNASTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeDownlinkNASTransportValueCodecFieldDecode(v *DownlinkNASTransportValueCodec) *func([]byte, aper.DecodeState) (DownlinkNASTransport, error) {
	return &v.decode
}
func BridgeDownlinkNASTransportValueCodecFieldEncode(v *DownlinkNASTransportValueCodec) *func(DownlinkNASTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDownlinkNASTransportValueCodecFieldPath(v *DownlinkNASTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeDownlinkNASTransportValueCodecMethodEncodeBudgetValue(v DownlinkNASTransportValueCodec, a0 DownlinkNASTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeDownlinkNASTransportValueCodecMethodEncodeChanged(v DownlinkNASTransportValueCodec, a0 DownlinkNASTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRestrictionListAPERValueFieldContext(v *HandoverRestrictionListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListAPERValueFieldReceived(v *HandoverRestrictionListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRestrictionListAPERValueFieldReplay(v *HandoverRestrictionListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListAPERValueFieldWithoutReplay(v *HandoverRestrictionListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListExtIETableMethodInfoCNTypeRestrictions(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoCNTypeRestrictions()
}
func BridgeHandoverRestrictionListExtIETableMethodInfoLastNGRANPLMNIdentity(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoLastNGRANPLMNIdentity()
}
func BridgeHandoverRestrictionListExtIETableMethodInfoNRrestrictionin5GS(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoNRrestrictionin5GS()
}
func BridgeHandoverRestrictionListExtIETableMethodInfoNRrestrictioninEPSasSecondaryRAT(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoNRrestrictioninEPSasSecondaryRAT()
}
func BridgeHandoverRestrictionListExtIETableMethodInfoRATRestrictions(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoRATRestrictions()
}
func BridgeHandoverRestrictionListExtIETableMethodInfoUnlicensedSpectrumRestriction(v HandoverRestrictionListExtIETable) s00.ExtensionInfo {
	return v.infoUnlicensedSpectrumRestriction()
}
func BridgeHandoverRestrictionListExtIEsCNTypeRestrictionsExtBindingFieldCodec(v *HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) *s14.CNTypeRestrictionsValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsCNTypeRestrictionsExtBindingFieldGet(v *HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s14.CNTypeRestrictions, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsCNTypeRestrictionsExtBindingFieldInfo(v *HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsCNTypeRestrictionsExtBindingFieldInject(v *HandoverRestrictionListExtIEsCNTypeRestrictionsExtBinding) *func(s14.CNTypeRestrictions) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsExtContainerAPERValueFieldContext(v *HandoverRestrictionListExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListExtIEsExtContainerAPERValueFieldReceived(v *HandoverRestrictionListExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRestrictionListExtIEsExtContainerAPERValueFieldReplay(v *HandoverRestrictionListExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListExtIEsExtContainerAPERValueFieldWithoutReplay(v *HandoverRestrictionListExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldCapture(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *func(HandoverRestrictionListExtIEsExtContainer, aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldCompare(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *func(HandoverRestrictionListExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldContext(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldDecode(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (HandoverRestrictionListExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldEncode(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *func(HandoverRestrictionListExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecFieldPath(v *HandoverRestrictionListExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v HandoverRestrictionListExtIEsExtContainerValueCodec, a0 HandoverRestrictionListExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRestrictionListExtIEsExtContainerValueCodecMethodEncodeChanged(v HandoverRestrictionListExtIEsExtContainerValueCodec, a0 HandoverRestrictionListExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRestrictionListExtIEsExtFieldAPERValueFieldContext(v *HandoverRestrictionListExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListExtIEsExtFieldAPERValueFieldReceived(v *HandoverRestrictionListExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRestrictionListExtIEsExtFieldAPERValueFieldReplay(v *HandoverRestrictionListExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListExtIEsExtFieldAPERValueFieldWithoutReplay(v *HandoverRestrictionListExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListExtIEsExtFieldFieldReceived(v *HandoverRestrictionListExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverRestrictionListExtIEsExtFieldFieldReplay(v *HandoverRestrictionListExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListExtIEsExtFieldFieldStream(v *HandoverRestrictionListExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRestrictionListExtIEsExtFieldFieldWithoutReplay(v *HandoverRestrictionListExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListExtIEsExtFieldMethodMarshalAPERTo(v *HandoverRestrictionListExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRestrictionListExtIEsExtFieldMethodUnmarshalAPERFrom(v *HandoverRestrictionListExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldCapture(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *func(HandoverRestrictionListExtIEsExtField, aper.DecodeState) (HandoverRestrictionListExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldCompare(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *func(HandoverRestrictionListExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldContext(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldDecode(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (HandoverRestrictionListExtIEsExtField, error) {
	return &v.decode
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldEncode(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *func(HandoverRestrictionListExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecFieldPath(v *HandoverRestrictionListExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v HandoverRestrictionListExtIEsExtFieldValueCodec, a0 HandoverRestrictionListExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRestrictionListExtIEsExtFieldValueCodecMethodEncodeChanged(v HandoverRestrictionListExtIEsExtFieldValueCodec, a0 HandoverRestrictionListExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHandoverRestrictionListExtIEsIEFieldFieldReceived(v *HandoverRestrictionListExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeHandoverRestrictionListExtIEsIEFieldFieldReplay(v *HandoverRestrictionListExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListExtIEsIEFieldFieldStream(v *HandoverRestrictionListExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRestrictionListExtIEsIEFieldFieldWithoutReplay(v *HandoverRestrictionListExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListExtIEsIEFieldMethodMarshalAPERTo(v *HandoverRestrictionListExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRestrictionListExtIEsIEFieldMethodUnmarshalAPERFrom(v *HandoverRestrictionListExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRestrictionListExtIEsNRrestrictionin5GSExtBindingFieldCodec(v *HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) *s01.NRrestrictionin5GSValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsNRrestrictionin5GSExtBindingFieldGet(v *HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s00.NRrestrictionin5GS, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsNRrestrictionin5GSExtBindingFieldInfo(v *HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsNRrestrictionin5GSExtBindingFieldInject(v *HandoverRestrictionListExtIEsNRrestrictionin5GSExtBinding) *func(s00.NRrestrictionin5GS) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBindingFieldCodec(v *HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) *s01.NRrestrictioninEPSasSecondaryRATValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBindingFieldGet(v *HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s00.NRrestrictioninEPSasSecondaryRAT, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBindingFieldInfo(v *HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBindingFieldInject(v *HandoverRestrictionListExtIEsNRrestrictioninEPSasSecondaryRATExtBinding) *func(s00.NRrestrictioninEPSasSecondaryRAT) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsPLMNidentityExtBindingFieldCodec(v *HandoverRestrictionListExtIEsPLMNidentityExtBinding) *s01.PLMNidentityValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsPLMNidentityExtBindingFieldGet(v *HandoverRestrictionListExtIEsPLMNidentityExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s00.PLMNidentity, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsPLMNidentityExtBindingFieldInfo(v *HandoverRestrictionListExtIEsPLMNidentityExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsPLMNidentityExtBindingFieldInject(v *HandoverRestrictionListExtIEsPLMNidentityExtBinding) *func(s00.PLMNidentity) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsRATRestrictionsExtBindingFieldCodec(v *HandoverRestrictionListExtIEsRATRestrictionsExtBinding) *s20.RATRestrictionsValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsRATRestrictionsExtBindingFieldGet(v *HandoverRestrictionListExtIEsRATRestrictionsExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s20.RATRestrictions, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsRATRestrictionsExtBindingFieldInfo(v *HandoverRestrictionListExtIEsRATRestrictionsExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsRATRestrictionsExtBindingFieldInject(v *HandoverRestrictionListExtIEsRATRestrictionsExtBinding) *func(s20.RATRestrictions) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBindingFieldCodec(v *HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) *s02.UnlicensedSpectrumRestrictionValueCodec {
	return &v.codec
}
func BridgeHandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBindingFieldGet(v *HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) *func(*HandoverRestrictionListExtIEsValue) (*s00.UnlicensedSpectrumRestriction, bool) {
	return &v.get
}
func BridgeHandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBindingFieldInfo(v *HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeHandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBindingFieldInject(v *HandoverRestrictionListExtIEsUnlicensedSpectrumRestrictionExtBinding) *func(s00.UnlicensedSpectrumRestriction) HandoverRestrictionListExtIEsValue {
	return &v.inject
}
func BridgeHandoverRestrictionListExtIEsValueFieldId(v *HandoverRestrictionListExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeHandoverRestrictionListExtIEsValueFieldIsOpaque(v *HandoverRestrictionListExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeHandoverRestrictionListExtIEsValueFieldOpaque(v *HandoverRestrictionListExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeHandoverRestrictionListExtIEsValueFieldReceived(v *HandoverRestrictionListExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRestrictionListExtIEsValueFieldReplay(v *HandoverRestrictionListExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowCNTypeRestrictions(v *HandoverRestrictionListExtIEsValue) **s14.CNTypeRestrictions {
	return &v.rowCNTypeRestrictions
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowLastNGRANPLMNIdentity(v *HandoverRestrictionListExtIEsValue) **s00.PLMNidentity {
	return &v.rowLastNGRANPLMNIdentity
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictionin5GS(v *HandoverRestrictionListExtIEsValue) **s00.NRrestrictionin5GS {
	return &v.rowNRrestrictionin5GS
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowNRrestrictioninEPSasSecondaryRAT(v *HandoverRestrictionListExtIEsValue) **s00.NRrestrictioninEPSasSecondaryRAT {
	return &v.rowNRrestrictioninEPSasSecondaryRAT
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowRATRestrictions(v *HandoverRestrictionListExtIEsValue) **s20.RATRestrictions {
	return &v.rowRATRestrictions
}
func BridgeHandoverRestrictionListExtIEsValueFieldRowUnlicensedSpectrumRestriction(v *HandoverRestrictionListExtIEsValue) **s00.UnlicensedSpectrumRestriction {
	return &v.rowUnlicensedSpectrumRestriction
}
func BridgeHandoverRestrictionListExtIEsValueMethodCaptureSemantics(v HandoverRestrictionListExtIEsValue, a0 aper.SemanticCapture) HandoverRestrictionListExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeHandoverRestrictionListExtIEsValueMethodCompareSemantics(v HandoverRestrictionListExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeHandoverRestrictionListExtIEsValueMethodDecode(v HandoverRestrictionListExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (HandoverRestrictionListExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeHandoverRestrictionListExtIEsValueMethodEncode(v HandoverRestrictionListExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeHandoverRestrictionListExtIEsValueMethodEncodeFresh(v HandoverRestrictionListExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeHandoverRestrictionListExtIEsValueMethodMatchesID(v HandoverRestrictionListExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeHandoverRestrictionListExtIEsValueMethodReason(v HandoverRestrictionListExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeHandoverRestrictionListExtIEsValueMethodRule(v HandoverRestrictionListExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeHandoverRestrictionListFieldEquivalentPLMNsIndef(v *HandoverRestrictionList) *bool {
	return &v.equivalentPLMNsIndef
}
func BridgeHandoverRestrictionListFieldExtCount(v *HandoverRestrictionList) *int64 {
	return &v.extCount
}
func BridgeHandoverRestrictionListFieldExtData(v *HandoverRestrictionList) *[][]byte {
	return &v.extData
}
func BridgeHandoverRestrictionListFieldExtOrigin(v *HandoverRestrictionList) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverRestrictionListFieldExtPresent(v *HandoverRestrictionList) *[]bool {
	return &v.extPresent
}
func BridgeHandoverRestrictionListFieldExtWire(v *HandoverRestrictionList) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeHandoverRestrictionListFieldForbiddenLAsIndef(v *HandoverRestrictionList) *bool {
	return &v.forbiddenLAsIndef
}
func BridgeHandoverRestrictionListFieldForbiddenTAsIndef(v *HandoverRestrictionList) *bool {
	return &v.forbiddenTAsIndef
}
func BridgeHandoverRestrictionListFieldIEExtensionsIndef(v *HandoverRestrictionList) *bool {
	return &v.iEExtensionsIndef
}
func BridgeHandoverRestrictionListFieldPerExtPadding(v *HandoverRestrictionList) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverRestrictionListFieldPerPadding(v *HandoverRestrictionList) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverRestrictionListFieldReceived(v *HandoverRestrictionList) *bool { return &v.received }
func BridgeHandoverRestrictionListFieldReceivedAbsolute(v *HandoverRestrictionList) *bool {
	return &v.receivedAbsolute
}
func BridgeHandoverRestrictionListFieldReceivedBytes(v *HandoverRestrictionList) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverRestrictionListFieldReceivedLocation(v *HandoverRestrictionList) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverRestrictionListFieldReplay(v *HandoverRestrictionList) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRestrictionListFieldStream(v *HandoverRestrictionList) *aper.WireSpan {
	return &v.stream
}
func BridgeHandoverRestrictionListFieldWithoutReplay(v *HandoverRestrictionList) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRestrictionListMethodMarshalAPERBudget(v *HandoverRestrictionList, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverRestrictionListMethodMarshalAPERBudgetValue(v *HandoverRestrictionList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverRestrictionListMethodMarshalAPERChanged(v *HandoverRestrictionList, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverRestrictionListMethodMarshalAPERChangedValue(v *HandoverRestrictionList, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverRestrictionListMethodMarshalAPERLegacy(v *HandoverRestrictionList) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverRestrictionListMethodMarshalAPERNewValue(v *HandoverRestrictionList, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverRestrictionListMethodMarshalAPERPlanned(v *HandoverRestrictionList, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverRestrictionListMethodMarshalAPERTo(v *HandoverRestrictionList, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRestrictionListMethodUnmarshalAPERFrom(v *HandoverRestrictionList, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRestrictionListMethodUnmarshalAPERLegacy(v *HandoverRestrictionList, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverRestrictionListMethodUnmarshalAPERWithOptions(v *HandoverRestrictionList, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverRestrictionListValueCodecFieldCapture(v *HandoverRestrictionListValueCodec) *func(HandoverRestrictionList, aper.DecodeState) (HandoverRestrictionList, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRestrictionListValueCodecFieldCompare(v *HandoverRestrictionListValueCodec) *func(HandoverRestrictionList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRestrictionListValueCodecFieldContext(v *HandoverRestrictionListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRestrictionListValueCodecFieldDecode(v *HandoverRestrictionListValueCodec) *func([]byte, aper.DecodeState) (HandoverRestrictionList, error) {
	return &v.decode
}
func BridgeHandoverRestrictionListValueCodecFieldEncode(v *HandoverRestrictionListValueCodec) *func(HandoverRestrictionList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRestrictionListValueCodecFieldPath(v *HandoverRestrictionListValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRestrictionListValueCodecMethodEncodeBudgetValue(v HandoverRestrictionListValueCodec, a0 HandoverRestrictionList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRestrictionListValueCodecMethodEncodeChanged(v HandoverRestrictionListValueCodec, a0 HandoverRestrictionList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNotificationCellListCompleteFieldPerPadding(v *NotificationCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeNotificationCellListCompleteFieldReceived(v *NotificationCellListComplete) *bool {
	return &v.received
}
func BridgeNotificationCellListCompleteFieldReceivedAbsolute(v *NotificationCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeNotificationCellListCompleteFieldReceivedBytes(v *NotificationCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNotificationCellListCompleteFieldReceivedLocation(v *NotificationCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeNotificationCellListCompleteFieldReplay(v *NotificationCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeNotificationCellListCompleteFieldStream(v *NotificationCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeNotificationCellListCompleteFieldWithoutReplay(v *NotificationCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeNotificationCellListCompleteMethodMarshalAPERBudget(v *NotificationCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNotificationCellListCompleteMethodMarshalAPERBudgetValue(v *NotificationCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeNotificationCellListCompleteMethodMarshalAPERChanged(v *NotificationCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNotificationCellListCompleteMethodMarshalAPERChangedValue(v *NotificationCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNotificationCellListCompleteMethodMarshalAPERLegacy(v *NotificationCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNotificationCellListCompleteMethodMarshalAPERNewValue(v *NotificationCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeNotificationCellListCompleteMethodMarshalAPERPlanned(v *NotificationCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeNotificationCellListCompleteMethodUnmarshalAPERLegacy(v *NotificationCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNotificationCellListCompleteMethodUnmarshalAPERWithOptions(v *NotificationCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePC5QoSFlowListCompleteFieldPerPadding(v *PC5QoSFlowListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePC5QoSFlowListCompleteFieldReceived(v *PC5QoSFlowListComplete) *bool { return &v.received }
func BridgePC5QoSFlowListCompleteFieldReceivedAbsolute(v *PC5QoSFlowListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgePC5QoSFlowListCompleteFieldReceivedBytes(v *PC5QoSFlowListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePC5QoSFlowListCompleteFieldReceivedLocation(v *PC5QoSFlowListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgePC5QoSFlowListCompleteFieldReplay(v *PC5QoSFlowListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgePC5QoSFlowListCompleteFieldStream(v *PC5QoSFlowListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgePC5QoSFlowListCompleteFieldWithoutReplay(v *PC5QoSFlowListComplete) *bool {
	return &v.withoutReplay
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERBudget(v *PC5QoSFlowListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERBudgetValue(v *PC5QoSFlowListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERChanged(v *PC5QoSFlowListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERChangedValue(v *PC5QoSFlowListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERLegacy(v *PC5QoSFlowListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERNewValue(v *PC5QoSFlowListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePC5QoSFlowListCompleteMethodMarshalAPERPlanned(v *PC5QoSFlowListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePC5QoSFlowListCompleteMethodUnmarshalAPERLegacy(v *PC5QoSFlowListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePC5QoSFlowListCompleteMethodUnmarshalAPERWithOptions(v *PC5QoSFlowListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePLMNListforQMCCompleteFieldPerPadding(v *PLMNListforQMCComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePLMNListforQMCCompleteFieldReceived(v *PLMNListforQMCComplete) *bool { return &v.received }
func BridgePLMNListforQMCCompleteFieldReceivedAbsolute(v *PLMNListforQMCComplete) *bool {
	return &v.receivedAbsolute
}
func BridgePLMNListforQMCCompleteFieldReceivedBytes(v *PLMNListforQMCComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePLMNListforQMCCompleteFieldReceivedLocation(v *PLMNListforQMCComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgePLMNListforQMCCompleteFieldReplay(v *PLMNListforQMCComplete) *aper.Snapshot {
	return &v.replay
}
func BridgePLMNListforQMCCompleteFieldStream(v *PLMNListforQMCComplete) *aper.WireSpan {
	return &v.stream
}
func BridgePLMNListforQMCCompleteFieldWithoutReplay(v *PLMNListforQMCComplete) *bool {
	return &v.withoutReplay
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERBudget(v *PLMNListforQMCComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERBudgetValue(v *PLMNListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERChanged(v *PLMNListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERChangedValue(v *PLMNListforQMCComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERLegacy(v *PLMNListforQMCComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERNewValue(v *PLMNListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePLMNListforQMCCompleteMethodMarshalAPERPlanned(v *PLMNListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePLMNListforQMCCompleteMethodUnmarshalAPERLegacy(v *PLMNListforQMCComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePLMNListforQMCCompleteMethodUnmarshalAPERWithOptions(v *PLMNListforQMCComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePWSFailureIndicationAPERValueFieldContext(v *PWSFailureIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationAPERValueFieldReceived(v *PWSFailureIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationAPERValueFieldReplay(v *PWSFailureIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationAPERValueFieldWithoutReplay(v *PWSFailureIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationFieldExtCount(v *PWSFailureIndication) *int64   { return &v.extCount }
func BridgePWSFailureIndicationFieldExtData(v *PWSFailureIndication) *[][]byte { return &v.extData }
func BridgePWSFailureIndicationFieldExtOrigin(v *PWSFailureIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePWSFailureIndicationFieldExtPresent(v *PWSFailureIndication) *[]bool { return &v.extPresent }
func BridgePWSFailureIndicationFieldExtWire(v *PWSFailureIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePWSFailureIndicationFieldPerExtPadding(v *PWSFailureIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePWSFailureIndicationFieldPerPadding(v *PWSFailureIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePWSFailureIndicationFieldProtocolIEsIndef(v *PWSFailureIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgePWSFailureIndicationFieldReceived(v *PWSFailureIndication) *bool { return &v.received }
func BridgePWSFailureIndicationFieldReceivedAbsolute(v *PWSFailureIndication) *bool {
	return &v.receivedAbsolute
}
func BridgePWSFailureIndicationFieldReceivedBytes(v *PWSFailureIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePWSFailureIndicationFieldReceivedLocation(v *PWSFailureIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgePWSFailureIndicationFieldReplay(v *PWSFailureIndication) *aper.Snapshot { return &v.replay }
func BridgePWSFailureIndicationFieldStream(v *PWSFailureIndication) *aper.WireSpan { return &v.stream }
func BridgePWSFailureIndicationFieldWithoutReplay(v *PWSFailureIndication) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationGlobalENBIDIEBindingFieldCodec(v *PWSFailureIndicationGlobalENBIDIEBinding) *s18.GlobalENBIDValueCodec {
	return &v.codec
}
func BridgePWSFailureIndicationGlobalENBIDIEBindingFieldGet(v *PWSFailureIndicationGlobalENBIDIEBinding) *func(*PWSFailureIndicationIEValue) (*s18.GlobalENBID, bool) {
	return &v.get
}
func BridgePWSFailureIndicationGlobalENBIDIEBindingFieldInfo(v *PWSFailureIndicationGlobalENBIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSFailureIndicationGlobalENBIDIEBindingFieldInject(v *PWSFailureIndicationGlobalENBIDIEBinding) *func(s18.GlobalENBID) PWSFailureIndicationIEValue {
	return &v.inject
}
func BridgePWSFailureIndicationIEContainerAPERValueFieldContext(v *PWSFailureIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEContainerAPERValueFieldReceived(v *PWSFailureIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEContainerAPERValueFieldReplay(v *PWSFailureIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEContainerAPERValueFieldWithoutReplay(v *PWSFailureIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldCapture(v *PWSFailureIndicationIEContainerValueCodec) *func(PWSFailureIndicationIEContainer, aper.DecodeState) (PWSFailureIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldCompare(v *PWSFailureIndicationIEContainerValueCodec) *func(PWSFailureIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldContext(v *PWSFailureIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldDecode(v *PWSFailureIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndicationIEContainer, error) {
	return &v.decode
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldEncode(v *PWSFailureIndicationIEContainerValueCodec) *func(PWSFailureIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationIEContainerValueCodecFieldPath(v *PWSFailureIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationIEContainerValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationIEContainerValueCodec, a0 PWSFailureIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationIEContainerValueCodecMethodEncodeChanged(v PWSFailureIndicationIEContainerValueCodec, a0 PWSFailureIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSFailureIndicationIEFieldAPERValueFieldContext(v *PWSFailureIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEFieldAPERValueFieldReceived(v *PWSFailureIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEFieldAPERValueFieldReplay(v *PWSFailureIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEFieldAPERValueFieldWithoutReplay(v *PWSFailureIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEFieldFieldReceived(v *PWSFailureIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePWSFailureIndicationIEFieldFieldReplay(v *PWSFailureIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEFieldFieldStream(v *PWSFailureIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePWSFailureIndicationIEFieldFieldWithoutReplay(v *PWSFailureIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEFieldMethodMarshalAPERTo(v *PWSFailureIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePWSFailureIndicationIEFieldMethodUnmarshalAPERFrom(v *PWSFailureIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldCapture(v *PWSFailureIndicationIEFieldValueCodec) *func(PWSFailureIndicationIEField, aper.DecodeState) (PWSFailureIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldCompare(v *PWSFailureIndicationIEFieldValueCodec) *func(PWSFailureIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldContext(v *PWSFailureIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldDecode(v *PWSFailureIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndicationIEField, error) {
	return &v.decode
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldEncode(v *PWSFailureIndicationIEFieldValueCodec) *func(PWSFailureIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationIEFieldValueCodecFieldPath(v *PWSFailureIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationIEFieldValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationIEFieldValueCodec, a0 PWSFailureIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationIEFieldValueCodecMethodEncodeChanged(v PWSFailureIndicationIEFieldValueCodec, a0 PWSFailureIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSFailureIndicationIETableMethodInfoGlobalENBID(v PWSFailureIndicationIETable) s00.FieldInfo {
	return v.infoGlobalENBID()
}
func BridgePWSFailureIndicationIETableMethodInfoPWSfailedECGIList(v PWSFailureIndicationIETable) s00.FieldInfo {
	return v.infoPWSfailedECGIList()
}
func BridgePWSFailureIndicationIEValueERABIEContainerListAPERValueFieldContext(v *PWSFailureIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *PWSFailureIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *PWSFailureIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PWSFailureIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *func(PWSFailureIndicationIEValueERABIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *func(PWSFailureIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *func(PWSFailureIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecFieldPath(v *PWSFailureIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationIEValueERABIEContainerListValueCodec, a0 PWSFailureIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PWSFailureIndicationIEValueERABIEContainerListValueCodec, a0 PWSFailureIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSFailureIndicationIEValueFieldId(v *PWSFailureIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePWSFailureIndicationIEValueFieldIsOpaque(v *PWSFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgePWSFailureIndicationIEValueFieldOpaque(v *PWSFailureIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePWSFailureIndicationIEValueFieldReceived(v *PWSFailureIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEValueFieldReplay(v *PWSFailureIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEValueFieldRowGlobalENBID(v *PWSFailureIndicationIEValue) **s18.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgePWSFailureIndicationIEValueFieldRowPWSfailedECGIList(v *PWSFailureIndicationIEValue) **s20.PWSfailedECGIList {
	return &v.rowPWSfailedECGIList
}
func BridgePWSFailureIndicationIEValueMethodCaptureSemantics(v PWSFailureIndicationIEValue, a0 aper.SemanticCapture) PWSFailureIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgePWSFailureIndicationIEValueMethodCompareSemantics(v PWSFailureIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePWSFailureIndicationIEValueMethodDecode(v PWSFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PWSFailureIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePWSFailureIndicationIEValueMethodEncode(v PWSFailureIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePWSFailureIndicationIEValueMethodEncodeFresh(v PWSFailureIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePWSFailureIndicationIEValueMethodMatchesID(v PWSFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePWSFailureIndicationIEValueMethodReason(v PWSFailureIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePWSFailureIndicationIEValueMethodRule(v PWSFailureIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 PWSFailureIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PWSFailureIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 PWSFailureIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PWSFailureIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolIEContainerList, aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSFailureIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *PWSFailureIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationIEValueProtocolIEContainerListValueCodec, a0 PWSFailureIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PWSFailureIndicationIEValueProtocolIEContainerListValueCodec, a0 PWSFailureIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSFailureIndicationMethodMarshalAPERBudget(v *PWSFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePWSFailureIndicationMethodMarshalAPERBudgetValue(v *PWSFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePWSFailureIndicationMethodMarshalAPERChanged(v *PWSFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePWSFailureIndicationMethodMarshalAPERChangedValue(v *PWSFailureIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePWSFailureIndicationMethodMarshalAPERLegacy(v *PWSFailureIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePWSFailureIndicationMethodMarshalAPERNewValue(v *PWSFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePWSFailureIndicationMethodMarshalAPERPlanned(v *PWSFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePWSFailureIndicationMethodMarshalAPERTo(v *PWSFailureIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePWSFailureIndicationMethodUnmarshalAPERFrom(v *PWSFailureIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePWSFailureIndicationMethodUnmarshalAPERLegacy(v *PWSFailureIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePWSFailureIndicationMethodUnmarshalAPERWithOptions(v *PWSFailureIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePWSFailureIndicationPWSfailedECGIListIEBindingFieldCodec(v *PWSFailureIndicationPWSfailedECGIListIEBinding) *s20.PWSfailedECGIListValueCodec {
	return &v.codec
}
func BridgePWSFailureIndicationPWSfailedECGIListIEBindingFieldGet(v *PWSFailureIndicationPWSfailedECGIListIEBinding) *func(*PWSFailureIndicationIEValue) (*s20.PWSfailedECGIList, bool) {
	return &v.get
}
func BridgePWSFailureIndicationPWSfailedECGIListIEBindingFieldInfo(v *PWSFailureIndicationPWSfailedECGIListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSFailureIndicationPWSfailedECGIListIEBindingFieldInject(v *PWSFailureIndicationPWSfailedECGIListIEBinding) *func(s20.PWSfailedECGIList) PWSFailureIndicationIEValue {
	return &v.inject
}
func BridgePWSFailureIndicationValueCodecFieldCapture(v *PWSFailureIndicationValueCodec) *func(PWSFailureIndication, aper.DecodeState) (PWSFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgePWSFailureIndicationValueCodecFieldCompare(v *PWSFailureIndicationValueCodec) *func(PWSFailureIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSFailureIndicationValueCodecFieldContext(v *PWSFailureIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSFailureIndicationValueCodecFieldDecode(v *PWSFailureIndicationValueCodec) *func([]byte, aper.DecodeState) (PWSFailureIndication, error) {
	return &v.decode
}
func BridgePWSFailureIndicationValueCodecFieldEncode(v *PWSFailureIndicationValueCodec) *func(PWSFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSFailureIndicationValueCodecFieldPath(v *PWSFailureIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSFailureIndicationValueCodecMethodEncodeBudgetValue(v PWSFailureIndicationValueCodec, a0 PWSFailureIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSFailureIndicationValueCodecMethodEncodeChanged(v PWSFailureIndicationValueCodec, a0 PWSFailureIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSfailedECGIListCompleteFieldPerPadding(v *PWSfailedECGIListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePWSfailedECGIListCompleteFieldReceived(v *PWSfailedECGIListComplete) *bool {
	return &v.received
}
func BridgePWSfailedECGIListCompleteFieldReceivedAbsolute(v *PWSfailedECGIListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgePWSfailedECGIListCompleteFieldReceivedBytes(v *PWSfailedECGIListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePWSfailedECGIListCompleteFieldReceivedLocation(v *PWSfailedECGIListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgePWSfailedECGIListCompleteFieldReplay(v *PWSfailedECGIListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgePWSfailedECGIListCompleteFieldStream(v *PWSfailedECGIListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgePWSfailedECGIListCompleteFieldWithoutReplay(v *PWSfailedECGIListComplete) *bool {
	return &v.withoutReplay
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERBudget(v *PWSfailedECGIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERBudgetValue(v *PWSfailedECGIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERChanged(v *PWSfailedECGIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERChangedValue(v *PWSfailedECGIListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERLegacy(v *PWSfailedECGIListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERNewValue(v *PWSfailedECGIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePWSfailedECGIListCompleteMethodMarshalAPERPlanned(v *PWSfailedECGIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePWSfailedECGIListCompleteMethodUnmarshalAPERLegacy(v *PWSfailedECGIListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePWSfailedECGIListCompleteMethodUnmarshalAPERWithOptions(v *PWSfailedECGIListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRATRestrictionsCompleteFieldPerPadding(v *RATRestrictionsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeRATRestrictionsCompleteFieldReceived(v *RATRestrictionsComplete) *bool { return &v.received }
func BridgeRATRestrictionsCompleteFieldReceivedAbsolute(v *RATRestrictionsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeRATRestrictionsCompleteFieldReceivedBytes(v *RATRestrictionsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRATRestrictionsCompleteFieldReceivedLocation(v *RATRestrictionsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeRATRestrictionsCompleteFieldReplay(v *RATRestrictionsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeRATRestrictionsCompleteFieldStream(v *RATRestrictionsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeRATRestrictionsCompleteFieldWithoutReplay(v *RATRestrictionsComplete) *bool {
	return &v.withoutReplay
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERBudget(v *RATRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERBudgetValue(v *RATRestrictionsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERChanged(v *RATRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERChangedValue(v *RATRestrictionsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERLegacy(v *RATRestrictionsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERNewValue(v *RATRestrictionsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRATRestrictionsCompleteMethodMarshalAPERPlanned(v *RATRestrictionsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRATRestrictionsCompleteMethodUnmarshalAPERLegacy(v *RATRestrictionsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRATRestrictionsCompleteMethodUnmarshalAPERWithOptions(v *RATRestrictionsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRecommendedCellListCompleteFieldPerPadding(v *RecommendedCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeRecommendedCellListCompleteFieldReceived(v *RecommendedCellListComplete) *bool {
	return &v.received
}
func BridgeRecommendedCellListCompleteFieldReceivedAbsolute(v *RecommendedCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedCellListCompleteFieldReceivedBytes(v *RecommendedCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedCellListCompleteFieldReceivedLocation(v *RecommendedCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedCellListCompleteFieldReplay(v *RecommendedCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedCellListCompleteFieldStream(v *RecommendedCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeRecommendedCellListCompleteFieldWithoutReplay(v *RecommendedCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERBudget(v *RecommendedCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERBudgetValue(v *RecommendedCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERChanged(v *RecommendedCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERChangedValue(v *RecommendedCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERLegacy(v *RecommendedCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERNewValue(v *RecommendedCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedCellListCompleteMethodMarshalAPERPlanned(v *RecommendedCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedCellListCompleteMethodUnmarshalAPERLegacy(v *RecommendedCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedCellListCompleteMethodUnmarshalAPERWithOptions(v *RecommendedCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRecommendedENBListCompleteFieldPerPadding(v *RecommendedENBListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeRecommendedENBListCompleteFieldReceived(v *RecommendedENBListComplete) *bool {
	return &v.received
}
func BridgeRecommendedENBListCompleteFieldReceivedAbsolute(v *RecommendedENBListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedENBListCompleteFieldReceivedBytes(v *RecommendedENBListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedENBListCompleteFieldReceivedLocation(v *RecommendedENBListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedENBListCompleteFieldReplay(v *RecommendedENBListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBListCompleteFieldStream(v *RecommendedENBListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeRecommendedENBListCompleteFieldWithoutReplay(v *RecommendedENBListComplete) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERBudget(v *RecommendedENBListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERBudgetValue(v *RecommendedENBListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERChanged(v *RecommendedENBListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERChangedValue(v *RecommendedENBListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERLegacy(v *RecommendedENBListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERNewValue(v *RecommendedENBListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedENBListCompleteMethodMarshalAPERPlanned(v *RecommendedENBListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedENBListCompleteMethodUnmarshalAPERLegacy(v *RecommendedENBListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedENBListCompleteMethodUnmarshalAPERWithOptions(v *RecommendedENBListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeReportingCellListCompleteFieldPerPadding(v *ReportingCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeReportingCellListCompleteFieldReceived(v *ReportingCellListComplete) *bool {
	return &v.received
}
func BridgeReportingCellListCompleteFieldReceivedAbsolute(v *ReportingCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeReportingCellListCompleteFieldReceivedBytes(v *ReportingCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeReportingCellListCompleteFieldReceivedLocation(v *ReportingCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeReportingCellListCompleteFieldReplay(v *ReportingCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeReportingCellListCompleteFieldStream(v *ReportingCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeReportingCellListCompleteFieldWithoutReplay(v *ReportingCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeReportingCellListCompleteMethodMarshalAPERBudget(v *ReportingCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeReportingCellListCompleteMethodMarshalAPERBudgetValue(v *ReportingCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeReportingCellListCompleteMethodMarshalAPERChanged(v *ReportingCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeReportingCellListCompleteMethodMarshalAPERChangedValue(v *ReportingCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeReportingCellListCompleteMethodMarshalAPERLegacy(v *ReportingCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeReportingCellListCompleteMethodMarshalAPERNewValue(v *ReportingCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeReportingCellListCompleteMethodMarshalAPERPlanned(v *ReportingCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeReportingCellListCompleteMethodUnmarshalAPERLegacy(v *ReportingCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeReportingCellListCompleteMethodUnmarshalAPERWithOptions(v *ReportingCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRequestedCellListCompleteFieldPerPadding(v *RequestedCellListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeRequestedCellListCompleteFieldReceived(v *RequestedCellListComplete) *bool {
	return &v.received
}
func BridgeRequestedCellListCompleteFieldReceivedAbsolute(v *RequestedCellListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeRequestedCellListCompleteFieldReceivedBytes(v *RequestedCellListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRequestedCellListCompleteFieldReceivedLocation(v *RequestedCellListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeRequestedCellListCompleteFieldReplay(v *RequestedCellListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestedCellListCompleteFieldStream(v *RequestedCellListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeRequestedCellListCompleteFieldWithoutReplay(v *RequestedCellListComplete) *bool {
	return &v.withoutReplay
}
func BridgeRequestedCellListCompleteMethodMarshalAPERBudget(v *RequestedCellListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRequestedCellListCompleteMethodMarshalAPERBudgetValue(v *RequestedCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRequestedCellListCompleteMethodMarshalAPERChanged(v *RequestedCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRequestedCellListCompleteMethodMarshalAPERChangedValue(v *RequestedCellListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRequestedCellListCompleteMethodMarshalAPERLegacy(v *RequestedCellListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRequestedCellListCompleteMethodMarshalAPERNewValue(v *RequestedCellListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRequestedCellListCompleteMethodMarshalAPERPlanned(v *RequestedCellListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRequestedCellListCompleteMethodUnmarshalAPERLegacy(v *RequestedCellListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRequestedCellListCompleteMethodUnmarshalAPERWithOptions(v *RequestedCellListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldPerPadding(v *SecondaryRATDataUsageReportListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldReceived(v *SecondaryRATDataUsageReportListComplete) *bool {
	return &v.received
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldReceivedAbsolute(v *SecondaryRATDataUsageReportListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldReceivedBytes(v *SecondaryRATDataUsageReportListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldReceivedLocation(v *SecondaryRATDataUsageReportListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldReplay(v *SecondaryRATDataUsageReportListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldStream(v *SecondaryRATDataUsageReportListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeSecondaryRATDataUsageReportListCompleteFieldWithoutReplay(v *SecondaryRATDataUsageReportListComplete) *bool {
	return &v.withoutReplay
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(v *SecondaryRATDataUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudgetValue(v *SecondaryRATDataUsageReportListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERChanged(v *SecondaryRATDataUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERChangedValue(v *SecondaryRATDataUsageReportListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERLegacy(v *SecondaryRATDataUsageReportListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERNewValue(v *SecondaryRATDataUsageReportListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERPlanned(v *SecondaryRATDataUsageReportListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodUnmarshalAPERLegacy(v *SecondaryRATDataUsageReportListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSecondaryRATDataUsageReportListCompleteMethodUnmarshalAPERWithOptions(v *SecondaryRATDataUsageReportListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSensorMeasConfigNameListCompleteFieldPerPadding(v *SensorMeasConfigNameListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSensorMeasConfigNameListCompleteFieldReceived(v *SensorMeasConfigNameListComplete) *bool {
	return &v.received
}
func BridgeSensorMeasConfigNameListCompleteFieldReceivedAbsolute(v *SensorMeasConfigNameListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeSensorMeasConfigNameListCompleteFieldReceivedBytes(v *SensorMeasConfigNameListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSensorMeasConfigNameListCompleteFieldReceivedLocation(v *SensorMeasConfigNameListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeSensorMeasConfigNameListCompleteFieldReplay(v *SensorMeasConfigNameListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeSensorMeasConfigNameListCompleteFieldStream(v *SensorMeasConfigNameListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeSensorMeasConfigNameListCompleteFieldWithoutReplay(v *SensorMeasConfigNameListComplete) *bool {
	return &v.withoutReplay
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERBudget(v *SensorMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERBudgetValue(v *SensorMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERChanged(v *SensorMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERChangedValue(v *SensorMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERLegacy(v *SensorMeasConfigNameListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERNewValue(v *SensorMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSensorMeasConfigNameListCompleteMethodMarshalAPERPlanned(v *SensorMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSensorMeasConfigNameListCompleteMethodUnmarshalAPERLegacy(v *SensorMeasConfigNameListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSensorMeasConfigNameListCompleteMethodUnmarshalAPERWithOptions(v *SensorMeasConfigNameListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeServedDCNsCompleteFieldPerPadding(v *ServedDCNsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeServedDCNsCompleteFieldReceived(v *ServedDCNsComplete) *bool { return &v.received }
func BridgeServedDCNsCompleteFieldReceivedAbsolute(v *ServedDCNsComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeServedDCNsCompleteFieldReceivedBytes(v *ServedDCNsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeServedDCNsCompleteFieldReceivedLocation(v *ServedDCNsComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeServedDCNsCompleteFieldReplay(v *ServedDCNsComplete) *aper.Snapshot { return &v.replay }
func BridgeServedDCNsCompleteFieldStream(v *ServedDCNsComplete) *aper.WireSpan { return &v.stream }
func BridgeServedDCNsCompleteFieldWithoutReplay(v *ServedDCNsComplete) *bool   { return &v.withoutReplay }
func BridgeServedDCNsCompleteMethodMarshalAPERBudget(v *ServedDCNsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeServedDCNsCompleteMethodMarshalAPERBudgetValue(v *ServedDCNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeServedDCNsCompleteMethodMarshalAPERChanged(v *ServedDCNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeServedDCNsCompleteMethodMarshalAPERChangedValue(v *ServedDCNsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeServedDCNsCompleteMethodMarshalAPERLegacy(v *ServedDCNsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeServedDCNsCompleteMethodMarshalAPERNewValue(v *ServedDCNsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeServedDCNsCompleteMethodMarshalAPERPlanned(v *ServedDCNsComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeServedDCNsCompleteMethodUnmarshalAPERLegacy(v *ServedDCNsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeServedDCNsCompleteMethodUnmarshalAPERWithOptions(v *ServedDCNsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseRequestAPERValueFieldContext(v *UEContextReleaseRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestAPERValueFieldReceived(v *UEContextReleaseRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestAPERValueFieldReplay(v *UEContextReleaseRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestAPERValueFieldWithoutReplay(v *UEContextReleaseRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestCauseIEBindingFieldCodec(v *UEContextReleaseRequestCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseRequestCauseIEBindingFieldGet(v *UEContextReleaseRequestCauseIEBinding) *func(*UEContextReleaseRequestIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeUEContextReleaseRequestCauseIEBindingFieldInfo(v *UEContextReleaseRequestCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestCauseIEBindingFieldInject(v *UEContextReleaseRequestCauseIEBinding) *func(s14.Cause) UEContextReleaseRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestENBUES1APIDIEBindingFieldCodec(v *UEContextReleaseRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseRequestENBUES1APIDIEBindingFieldGet(v *UEContextReleaseRequestENBUES1APIDIEBinding) *func(*UEContextReleaseRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeUEContextReleaseRequestENBUES1APIDIEBindingFieldInfo(v *UEContextReleaseRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestENBUES1APIDIEBindingFieldInject(v *UEContextReleaseRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) UEContextReleaseRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestFieldExtCount(v *UEContextReleaseRequest) *int64 {
	return &v.extCount
}
func BridgeUEContextReleaseRequestFieldExtData(v *UEContextReleaseRequest) *[][]byte {
	return &v.extData
}
func BridgeUEContextReleaseRequestFieldExtOrigin(v *UEContextReleaseRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextReleaseRequestFieldExtPresent(v *UEContextReleaseRequest) *[]bool {
	return &v.extPresent
}
func BridgeUEContextReleaseRequestFieldExtWire(v *UEContextReleaseRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextReleaseRequestFieldPerExtPadding(v *UEContextReleaseRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextReleaseRequestFieldPerPadding(v *UEContextReleaseRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseRequestFieldProtocolIEsIndef(v *UEContextReleaseRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextReleaseRequestFieldReceived(v *UEContextReleaseRequest) *bool { return &v.received }
func BridgeUEContextReleaseRequestFieldReceivedAbsolute(v *UEContextReleaseRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseRequestFieldReceivedBytes(v *UEContextReleaseRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseRequestFieldReceivedLocation(v *UEContextReleaseRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseRequestFieldReplay(v *UEContextReleaseRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestFieldStream(v *UEContextReleaseRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseRequestFieldWithoutReplay(v *UEContextReleaseRequest) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestGWContextReleaseIndicationIEBindingFieldCodec(v *UEContextReleaseRequestGWContextReleaseIndicationIEBinding) *s00.GWContextReleaseIndicationValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseRequestGWContextReleaseIndicationIEBindingFieldGet(v *UEContextReleaseRequestGWContextReleaseIndicationIEBinding) *func(*UEContextReleaseRequestIEValue) (*s00.GWContextReleaseIndication, bool) {
	return &v.get
}
func BridgeUEContextReleaseRequestGWContextReleaseIndicationIEBindingFieldInfo(v *UEContextReleaseRequestGWContextReleaseIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestGWContextReleaseIndicationIEBindingFieldInject(v *UEContextReleaseRequestGWContextReleaseIndicationIEBinding) *func(s00.GWContextReleaseIndication) UEContextReleaseRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestIEContainerAPERValueFieldContext(v *UEContextReleaseRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEContainerAPERValueFieldReceived(v *UEContextReleaseRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEContainerAPERValueFieldReplay(v *UEContextReleaseRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEContainerAPERValueFieldWithoutReplay(v *UEContextReleaseRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldCapture(v *UEContextReleaseRequestIEContainerValueCodec) *func(UEContextReleaseRequestIEContainer, aper.DecodeState) (UEContextReleaseRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldCompare(v *UEContextReleaseRequestIEContainerValueCodec) *func(UEContextReleaseRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldContext(v *UEContextReleaseRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldDecode(v *UEContextReleaseRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequestIEContainer, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldEncode(v *UEContextReleaseRequestIEContainerValueCodec) *func(UEContextReleaseRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestIEContainerValueCodecFieldPath(v *UEContextReleaseRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestIEContainerValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestIEContainerValueCodec, a0 UEContextReleaseRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestIEContainerValueCodecMethodEncodeChanged(v UEContextReleaseRequestIEContainerValueCodec, a0 UEContextReleaseRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseRequestIEFieldAPERValueFieldContext(v *UEContextReleaseRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEFieldAPERValueFieldReceived(v *UEContextReleaseRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEFieldAPERValueFieldReplay(v *UEContextReleaseRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEFieldAPERValueFieldWithoutReplay(v *UEContextReleaseRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEFieldFieldReceived(v *UEContextReleaseRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextReleaseRequestIEFieldFieldReplay(v *UEContextReleaseRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEFieldFieldStream(v *UEContextReleaseRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseRequestIEFieldFieldWithoutReplay(v *UEContextReleaseRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEFieldMethodMarshalAPERTo(v *UEContextReleaseRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseRequestIEFieldMethodUnmarshalAPERFrom(v *UEContextReleaseRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldCapture(v *UEContextReleaseRequestIEFieldValueCodec) *func(UEContextReleaseRequestIEField, aper.DecodeState) (UEContextReleaseRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldCompare(v *UEContextReleaseRequestIEFieldValueCodec) *func(UEContextReleaseRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldContext(v *UEContextReleaseRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldDecode(v *UEContextReleaseRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequestIEField, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldEncode(v *UEContextReleaseRequestIEFieldValueCodec) *func(UEContextReleaseRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestIEFieldValueCodecFieldPath(v *UEContextReleaseRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestIEFieldValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestIEFieldValueCodec, a0 UEContextReleaseRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestIEFieldValueCodecMethodEncodeChanged(v UEContextReleaseRequestIEFieldValueCodec, a0 UEContextReleaseRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseRequestIETableMethodInfoCause(v UEContextReleaseRequestIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUEContextReleaseRequestIETableMethodInfoENBUES1APID(v UEContextReleaseRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeUEContextReleaseRequestIETableMethodInfoGWContextReleaseIndication(v UEContextReleaseRequestIETable) s00.FieldInfo {
	return v.infoGWContextReleaseIndication()
}
func BridgeUEContextReleaseRequestIETableMethodInfoMMEUES1APID(v UEContextReleaseRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeUEContextReleaseRequestIETableMethodInfoSecondaryRATDataUsageReportList(v UEContextReleaseRequestIETable) s00.FieldInfo {
	return v.infoSecondaryRATDataUsageReportList()
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListAPERValueFieldContext(v *UEContextReleaseRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextReleaseRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextReleaseRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldContext(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecFieldPath(v *UEContextReleaseRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestIEValueERABIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseRequestIEValueERABIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseRequestIEValueFieldId(v *UEContextReleaseRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextReleaseRequestIEValueFieldIsOpaque(v *UEContextReleaseRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextReleaseRequestIEValueFieldOpaque(v *UEContextReleaseRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextReleaseRequestIEValueFieldReceived(v *UEContextReleaseRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEValueFieldReplay(v *UEContextReleaseRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEValueFieldRowCause(v *UEContextReleaseRequestIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeUEContextReleaseRequestIEValueFieldRowENBUES1APID(v *UEContextReleaseRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeUEContextReleaseRequestIEValueFieldRowGWContextReleaseIndication(v *UEContextReleaseRequestIEValue) **s00.GWContextReleaseIndication {
	return &v.rowGWContextReleaseIndication
}
func BridgeUEContextReleaseRequestIEValueFieldRowMMEUES1APID(v *UEContextReleaseRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeUEContextReleaseRequestIEValueFieldRowSecondaryRATDataUsageReportList(v *UEContextReleaseRequestIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeUEContextReleaseRequestIEValueMethodCaptureSemantics(v UEContextReleaseRequestIEValue, a0 aper.SemanticCapture) UEContextReleaseRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextReleaseRequestIEValueMethodCompareSemantics(v UEContextReleaseRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextReleaseRequestIEValueMethodDecode(v UEContextReleaseRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextReleaseRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextReleaseRequestIEValueMethodEncode(v UEContextReleaseRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextReleaseRequestIEValueMethodEncodeFresh(v UEContextReleaseRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextReleaseRequestIEValueMethodMatchesID(v UEContextReleaseRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextReleaseRequestIEValueMethodReason(v UEContextReleaseRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextReleaseRequestIEValueMethodRule(v UEContextReleaseRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseRequestIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseRequestIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseRequestMMEUES1APIDIEBindingFieldCodec(v *UEContextReleaseRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseRequestMMEUES1APIDIEBindingFieldGet(v *UEContextReleaseRequestMMEUES1APIDIEBinding) *func(*UEContextReleaseRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeUEContextReleaseRequestMMEUES1APIDIEBindingFieldInfo(v *UEContextReleaseRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestMMEUES1APIDIEBindingFieldInject(v *UEContextReleaseRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) UEContextReleaseRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v *UEContextReleaseRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERBudgetValue(v *UEContextReleaseRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERChanged(v *UEContextReleaseRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERChangedValue(v *UEContextReleaseRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERLegacy(v *UEContextReleaseRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextReleaseRequestMethodMarshalAPERNewValue(v *UEContextReleaseRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERPlanned(v *UEContextReleaseRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextReleaseRequestMethodMarshalAPERTo(v *UEContextReleaseRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseRequestMethodUnmarshalAPERFrom(v *UEContextReleaseRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseRequestMethodUnmarshalAPERLegacy(v *UEContextReleaseRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextReleaseRequestMethodUnmarshalAPERWithOptions(v *UEContextReleaseRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseRequestSecondaryRATDataUsageReportListIEBindingFieldCodec(v *UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseRequestSecondaryRATDataUsageReportListIEBindingFieldGet(v *UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) *func(*UEContextReleaseRequestIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeUEContextReleaseRequestSecondaryRATDataUsageReportListIEBindingFieldInfo(v *UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseRequestSecondaryRATDataUsageReportListIEBindingFieldInject(v *UEContextReleaseRequestSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) UEContextReleaseRequestIEValue {
	return &v.inject
}
func BridgeUEContextReleaseRequestValueCodecFieldCapture(v *UEContextReleaseRequestValueCodec) *func(UEContextReleaseRequest, aper.DecodeState) (UEContextReleaseRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseRequestValueCodecFieldCompare(v *UEContextReleaseRequestValueCodec) *func(UEContextReleaseRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseRequestValueCodecFieldContext(v *UEContextReleaseRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseRequestValueCodecFieldDecode(v *UEContextReleaseRequestValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseRequest, error) {
	return &v.decode
}
func BridgeUEContextReleaseRequestValueCodecFieldEncode(v *UEContextReleaseRequestValueCodec) *func(UEContextReleaseRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseRequestValueCodecFieldPath(v *UEContextReleaseRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseRequestValueCodecMethodEncodeBudgetValue(v UEContextReleaseRequestValueCodec, a0 UEContextReleaseRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseRequestValueCodecMethodEncodeChanged(v UEContextReleaseRequestValueCodec, a0 UEContextReleaseRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
