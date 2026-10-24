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
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverRequiredIEContainer is the concrete ProtocolIEContainer[HandoverRequiredIEValue].
type HandoverRequiredIEContainer []HandoverRequiredIEField

// HandoverRequiredIEField is the concrete ProtocolIEField[HandoverRequiredIEValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}
func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(v *s33.ENBDirectInformationTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainer(v *s33.ENBDirectInformationTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(v *s33.MMEDirectInformationTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainer(v *s33.MMEDirectInformationTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionContainer(v *SONInformationReplyExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionContainer(v *SONInformationReplyExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
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
func BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TimeBasedHandoverInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TimeBasedHandoverInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TimeSynchronisationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TimeSynchronisationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainer(v *s20.TraceFailureIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainer(v *s20.TraceFailureIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s11.TunnelInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s11.TunnelInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SONInformationReplyExtIEsExtContainer is the concrete ProtocolExtensionContainer[SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsExtContainer []SONInformationReplyExtIEsExtField

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer is the concrete ProtocolExtensionContainer[SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer []SourceeNBToTargeteNBTransparentContainerExtIEsExtField

// SONInformationReplyExtIEsExtField is the concrete ProtocolExtensionField[SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue SONInformationReplyExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReplyExtIEsExtField) WithoutReplay() SONInformationReplyExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONInformationReplyExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONInformationReplyExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *SONInformationReplyExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReplyExtIEsExtField{}
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
	var zero SONInformationReplyExtIEsValue

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

// SourceeNBToTargeteNBTransparentContainerExtIEsExtField is the concrete ProtocolExtensionField[SourceeNBToTargeteNBTransparentContainerExtIEsValue].
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
	var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue

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

// SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding is the concrete ExtensionBinding[TimeSynchronisationInfo, SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  TimeSynchronisationInfoValueCodec
	inject func(TimeSynchronisationInfo,

	) SONInformationReplyExtIEsValue

	get func(*SONInformationReplyExtIEsValue,

	) (*TimeSynchronisationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) Codec() TimeSynchronisationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) New(value TimeSynchronisationInfo,

) (SONInformationReplyExtIEsExtField, error) {
	if b.inject == nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONInformationReplyExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) Get(field *SONInformationReplyExtIEsExtField) (*TimeSynchronisationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TimeSynchronisationInfoValueCodec is the concrete ValueCodec[TimeSynchronisationInfo].
type TimeSynchronisationInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TimeSynchronisationInfo,

		error)
	encode func(TimeSynchronisationInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TimeSynchronisationInfo, aper.DecodeState,

	) (TimeSynchronisationInfo, aper.Snapshot,

	)
	compare func(TimeSynchronisationInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeSynchronisationInfoValueCodec) New(value TimeSynchronisationInfo,

) (TimeSynchronisationInfoAPERValue, error) {
	if c.encode == nil {
		return TimeSynchronisationInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeSynchronisationInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeSynchronisationInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeSynchronisationInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeSynchronisationInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeSynchronisationInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeSynchronisationInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeSynchronisationInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeSynchronisationInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeSynchronisationInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeSynchronisationInfoValueCodec) EncodeAPER(value TimeSynchronisationInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TimeSynchronisationInfoValueCodec) encodeBudgetValue(value TimeSynchronisationInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeSynchronisationInfoValueCodec) encodeChanged(value TimeSynchronisationInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationReplyExtIEsMutingPatternInformationExtBinding is the concrete ExtensionBinding[MutingPatternInformation, SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsMutingPatternInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.MutingPatternInformationValueCodec
	inject func(s19.MutingPatternInformation,

	) SONInformationReplyExtIEsValue

	get func(*SONInformationReplyExtIEsValue,

	) (*s19.MutingPatternInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONInformationReplyExtIEsMutingPatternInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONInformationReplyExtIEsMutingPatternInformationExtBinding) Codec() s19.MutingPatternInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONInformationReplyExtIEsMutingPatternInformationExtBinding) New(value s19.MutingPatternInformation,

) (SONInformationReplyExtIEsExtField, error) {
	if b.inject == nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeMutingPatternInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONInformationReplyExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONInformationReplyExtIEsMutingPatternInformationExtBinding) Get(field *SONInformationReplyExtIEsExtField) (*s19.MutingPatternInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding is the concrete ExtensionBinding[S1APIEsMobilityInformation, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.S1APIEsMobilityInformationValueCodec
	inject func(s00.S1APIEsMobilityInformation,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.S1APIEsMobilityInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) Codec() s01.S1APIEsMobilityInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) New(value s00.S1APIEsMobilityInformation,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeS1APIEsMobilityInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.S1APIEsMobilityInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding is the concrete ExtensionBinding[UEHistoryInformationFromTheUE, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding struct {
	info   s00.ExtensionInfo
	codec  s02.UEHistoryInformationFromTheUEValueCodec
	inject func(s00.UEHistoryInformationFromTheUE,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.UEHistoryInformationFromTheUE,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) Codec() s02.UEHistoryInformationFromTheUEValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) New(value s00.UEHistoryInformationFromTheUE,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.UEHistoryInformationFromTheUE,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding is the concrete ExtensionBinding[IMSvoiceEPSfallbackfrom5G, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding struct {
	info   s00.ExtensionInfo
	codec  s01.IMSvoiceEPSfallbackfrom5GValueCodec
	inject func(s00.IMSvoiceEPSfallbackfrom5G,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s00.IMSvoiceEPSfallbackfrom5G,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) Codec() s01.IMSvoiceEPSfallbackfrom5GValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) New(value s00.IMSvoiceEPSfallbackfrom5G,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s00.IMSvoiceEPSfallbackfrom5G,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding is the concrete ExtensionBinding[AdditionalRRMPriorityIndex, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
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

// SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding is the concrete ExtensionBinding[ContextatSource, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.ContextatSourceValueCodec
	inject func(s19.ContextatSource,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s19.ContextatSource,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Codec() s19.ContextatSourceValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) New(value s19.ContextatSource,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeContextatSourceValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s19.ContextatSource,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding is the concrete ExtensionBinding[IntersystemMeasurementConfiguration, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s24.IntersystemMeasurementConfigurationValueCodec
	inject func(s24.IntersystemMeasurementConfiguration,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s24.IntersystemMeasurementConfiguration,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) Codec() s24.IntersystemMeasurementConfigurationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) New(value s24.IntersystemMeasurementConfiguration,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s24.IntersystemMeasurementConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding is the concrete ExtensionBinding[SourceNodeID, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s30.SourceNodeIDValueCodec
	inject func(s30.SourceNodeID,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s30.SourceNodeID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Codec() s30.SourceNodeIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) New(value s30.SourceNodeID,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeSourceNodeIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s30.SourceNodeID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding is the concrete ExtensionBinding[EmergencyIndicator, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
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

// SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding is the concrete ExtensionBinding[ENBUES1APID, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
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

// SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding is the concrete ExtensionBinding[GlobalRANNODEID, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s19.GlobalRANNODEIDValueCodec
	inject func(s19.GlobalRANNODEID,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s19.GlobalRANNODEID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) Codec() s19.GlobalRANNODEIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) New(value s19.GlobalRANNODEID,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeGlobalRANNODEIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s19.GlobalRANNODEID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding is the concrete ExtensionBinding[DirectForwardingPathAvailability, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
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

// SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding is the concrete ExtensionBinding[TimeBasedHandoverInformation, SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  TimeBasedHandoverInformationValueCodec
	inject func(TimeBasedHandoverInformation,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*TimeBasedHandoverInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) Codec() TimeBasedHandoverInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) New(value TimeBasedHandoverInformation,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*TimeBasedHandoverInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// TimeBasedHandoverInformationValueCodec is the concrete ValueCodec[TimeBasedHandoverInformation].
type TimeBasedHandoverInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TimeBasedHandoverInformation,

		error)
	encode func(TimeBasedHandoverInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TimeBasedHandoverInformation, aper.DecodeState,

	) (TimeBasedHandoverInformation, aper.Snapshot,

	)
	compare func(TimeBasedHandoverInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeBasedHandoverInformationValueCodec) New(value TimeBasedHandoverInformation,

) (TimeBasedHandoverInformationAPERValue, error) {
	if c.encode == nil {
		return TimeBasedHandoverInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeBasedHandoverInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeBasedHandoverInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeBasedHandoverInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeBasedHandoverInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeBasedHandoverInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeBasedHandoverInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeBasedHandoverInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeBasedHandoverInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeBasedHandoverInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeBasedHandoverInformationValueCodec) EncodeAPER(value TimeBasedHandoverInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TimeBasedHandoverInformationValueCodec) encodeBudgetValue(value TimeBasedHandoverInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeBasedHandoverInformationValueCodec) encodeChanged(value TimeBasedHandoverInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequiredMMEUES1APIDIEBinding is the concrete IEBinding[MMEUES1APID, HandoverRequiredIEValue].
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

// HandoverRequiredENBUES1APIDIEBinding is the concrete IEBinding[ENBUES1APID, HandoverRequiredIEValue].
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

// HandoverRequiredHandoverTypeIEBinding is the concrete IEBinding[HandoverType, HandoverRequiredIEValue].
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

// HandoverRequiredCauseIEBinding is the concrete IEBinding[Cause, HandoverRequiredIEValue].
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

// HandoverRequiredTargetIDIEBinding is the concrete IEBinding[TargetID, HandoverRequiredIEValue].
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

// HandoverRequiredDirectForwardingPathAvailabilityIEBinding is the concrete IEBinding[DirectForwardingPathAvailability, HandoverRequiredIEValue].
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

// HandoverRequiredSRVCCHOIndicationIEBinding is the concrete IEBinding[SRVCCHOIndication, HandoverRequiredIEValue].
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

// HandoverRequiredSourceToTargetTransparentContainerIEBinding is the concrete IEBinding[SourceToTargetTransparentContainer, HandoverRequiredIEValue].
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

// HandoverRequiredMSClassmark2IEBinding is the concrete IEBinding[MSClassmark2, HandoverRequiredIEValue].
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

// HandoverRequiredMSClassmark3IEBinding is the concrete IEBinding[MSClassmark3, HandoverRequiredIEValue].
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

// HandoverRequiredCSGIdIEBinding is the concrete IEBinding[CSGId, HandoverRequiredIEValue].
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

// HandoverRequiredCellAccessModeIEBinding is the concrete IEBinding[CellAccessMode, HandoverRequiredIEValue].
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

// HandoverRequiredPSServiceNotAvailableIEBinding is the concrete IEBinding[PSServiceNotAvailable, HandoverRequiredIEValue].
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
	decode  func([]byte, aper.DecodeState) (s33.RIMTransfer,

		error)
	encode func(s33.RIMTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s33.RIMTransfer, aper.DecodeState,

	) (s33.RIMTransfer, aper.Snapshot,

	)
	compare func(s33.RIMTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMTransferValueCodec) New(value s33.RIMTransfer,

) (s33.RIMTransferAPERValue, error) {
	if c.encode == nil {
		return s33.RIMTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s33.RIMTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s33.RIMTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s33.RIMTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s33.RIMTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s33.RIMTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s33.RIMTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s33.RIMTransferAPERValue {
			sealed := s33.RIMTransferAPERValue{Value: value}
			*s33.BridgeRIMTransferAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s33.BridgeRIMTransferAPERValueFieldReplay(&sealed) = replay
			*s33.BridgeRIMTransferAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s33.RIMTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMTransferValueCodec) EncodeAPER(value s33.RIMTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s33.BridgeRIMTransferAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s33.BridgeRIMTransferAPERValueFieldContext(&value) == c.context && !fresh && (*s33.BridgeRIMTransferAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s33.BridgeRIMTransferAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s33.BridgeRIMTransferAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s33.BridgeRIMTransferAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c RIMTransferValueCodec) encodeBudgetValue(value s33.RIMTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMTransferValueCodec) encodeChanged(value s33.RIMTransfer,

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
	decode  func([]byte, aper.DecodeState) (s33.TargetRNCID,

		error)
	encode func(s33.TargetRNCID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s33.TargetRNCID, aper.DecodeState,

	) (s33.TargetRNCID, aper.Snapshot,

	)
	compare func(s33.TargetRNCID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCIDValueCodec) New(value s33.TargetRNCID,

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
func (c TargetRNCIDValueCodec) encodeBudgetValue(value s33.TargetRNCID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCIDValueCodec) encodeChanged(value s33.TargetRNCID,

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

// TraceFailureIndicationValueCodec is the concrete ValueCodec[TraceFailureIndication].
type TraceFailureIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceFailureIndication,

		error)
	encode func(TraceFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceFailureIndication, aper.DecodeState,

	) (TraceFailureIndication, aper.Snapshot,

	)
	compare func(TraceFailureIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceFailureIndicationValueCodec) New(value TraceFailureIndication,

) (TraceFailureIndicationAPERValue, error) {
	if c.encode == nil {
		return TraceFailureIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceFailureIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceFailureIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceFailureIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceFailureIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceFailureIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceFailureIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceFailureIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceFailureIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceFailureIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceFailureIndicationValueCodec) EncodeAPER(value TraceFailureIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TraceFailureIndicationValueCodec) encodeBudgetValue(value TraceFailureIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceFailureIndicationValueCodec) encodeChanged(value TraceFailureIndication,

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
func BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(fields s20.TraceFailureIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s20.BridgeTraceFailureIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s20.BridgeTraceFailureIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s20.BridgeTraceFailureIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields s33.ENBDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s33.BridgeENBDirectInformationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s33.BridgeENBDirectInformationTransferIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s33.BridgeENBDirectInformationTransferIEValueMethodRule(field.Value).Assignment
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
func BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields s33.MMEDirectInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s33.BridgeMMEDirectInformationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s33.BridgeMMEDirectInformationTransferIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s33.BridgeMMEDirectInformationTransferIEValueMethodRule(field.Value).Assignment
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
func BridgeSONInformationReplyExtIEsValueValidateS1APExtensionContainer(fields SONInformationReplyExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[SONInformationReplyExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(SONInformationReplyExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSONInformationReplyExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[SourceeNBToTargeteNBTransparentContainerExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(SourceeNBToTargeteNBTransparentContainerExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
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
func BridgeTargeteNBIDExtIEsValueValidateS1APExtensionContainer(fields s11.TargeteNBIDExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TargeteNBIDExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TargeteNBIDExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTargeteNBIDExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APExtensionContainer(fields s11.TimeBasedHandoverInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TimeBasedHandoverInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TimeBasedHandoverInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeTimeSynchronisationInfoExtIEsValueValidateS1APExtensionContainer(fields s11.TimeSynchronisationInfoExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.TimeSynchronisationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s11.TimeSynchronisationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTimeSynchronisationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func ENBDirectInformationTransferIEValueERABIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) s33.ENBDirectInformationTransferIEValueERABIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s33.ENBDirectInformationTransferIEValueERABIEContainerListValueCodec {
		sealed := s33.ENBDirectInformationTransferIEValueERABIEContainerListValueCodec{}
		*s33.BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueERABIEContainerList, error) {
			value, err := (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.ENBDirectInformationTransferIEValueERABIEContainerList(value), err
		}
		*s33.BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.ENBDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.ENBDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.ENBDirectInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.ENBDirectInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeENBDirectInformationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverRequiredIEValueERABIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEValueERABIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequiredIEValueERABIEContainerListValueCodec{}
	}
	return HandoverRequiredIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequiredIEValueERABIEContainerList(value), err
	}, encode: func(value HandoverRequiredIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequiredIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequiredIEValueERABIEContainerList, options aper.DecodeState) (HandoverRequiredIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v HandoverRequiredIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APERABIEContainerList(&v, &s)
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
func MMEDirectInformationTransferIEValueERABIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable) s33.MMEDirectInformationTransferIEValueERABIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.MMEDirectInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s33.MMEDirectInformationTransferIEValueERABIEContainerListValueCodec {
		sealed := s33.MMEDirectInformationTransferIEValueERABIEContainerListValueCodec{}
		*s33.BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueERABIEContainerList, error) {
			value, err := (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.MMEDirectInformationTransferIEValueERABIEContainerList(value), err
		}
		*s33.BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.MMEDirectInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.MMEDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.MMEDirectInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.MMEDirectInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeMMEDirectInformationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TraceFailureIndicationIEValueERABIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable) s20.TraceFailureIndicationIEValueERABIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.TraceFailureIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s20.TraceFailureIndicationIEValueERABIEContainerListValueCodec {
		sealed := s20.TraceFailureIndicationIEValueERABIEContainerListValueCodec{}
		*s20.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.TraceFailureIndicationIEValueERABIEContainerList, error) {
			value, err := (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s20.TraceFailureIndicationIEValueERABIEContainerList(value), err
		}
		*s20.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.TraceFailureIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s20.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s20.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.TraceFailureIndicationIEValueERABIEContainerList, options aper.DecodeState) (s20.TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.TraceFailureIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SONInformationReplyExtIEsValueExtensionFieldTableCodec(table s00.SONInformationReplyExtIEsValueExtensionTable) SONInformationReplyExtIEsExtFieldValueCodec {
	if !*s00.BridgeSONInformationReplyExtIEsValueExtensionTableFieldBound(&table) {
		return SONInformationReplyExtIEsExtFieldValueCodec{}
	}
	return SONInformationReplyExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (SONInformationReplyExtIEsExtField, error) {
		var field SONInformationReplyExtIEsExtField
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
	}, encode: func(field SONInformationReplyExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v SONInformationReplyExtIEsExtField, options aper.DecodeState) (SONInformationReplyExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v SONInformationReplyExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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
func SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionFieldTableCodec(table s00.SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTable) SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec {
	if !*s00.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec{}
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
		var field SourceeNBToTargeteNBTransparentContainerExtIEsExtField
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
	}, encode: func(field SourceeNBToTargeteNBTransparentContainerExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v SourceeNBToTargeteNBTransparentContainerExtIEsExtField, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,
			false)
		return v, root
	}, compare: func(v SourceeNBToTargeteNBTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTargeteNBIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargeteNBIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargeteNBIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
func TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec(table s00.TimeBasedHandoverInformationExtIEsValueExtensionTable) s11.TimeBasedHandoverInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeTimeBasedHandoverInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TimeBasedHandoverInformationExtIEsExtFieldValueCodec{}
	}
	return func() s11.TimeBasedHandoverInformationExtIEsExtFieldValueCodec {
		sealed := s11.TimeBasedHandoverInformationExtIEsExtFieldValueCodec{}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TimeBasedHandoverInformationExtIEsExtField, error) {
			var field s11.TimeBasedHandoverInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TimeBasedHandoverInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TimeBasedHandoverInformationExtIEsExtField, options aper.DecodeState) (s11.TimeBasedHandoverInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TimeBasedHandoverInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TimeSynchronisationInfoExtIEsValueExtensionFieldTableCodec(table s00.TimeSynchronisationInfoExtIEsValueExtensionTable) s11.TimeSynchronisationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeTimeSynchronisationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TimeSynchronisationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s11.TimeSynchronisationInfoExtIEsExtFieldValueCodec {
		sealed := s11.TimeSynchronisationInfoExtIEsExtFieldValueCodec{}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtField, error) {
			var field s11.TimeSynchronisationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TimeSynchronisationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtField, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TunnelInformationExtIEsValueExtensionFieldTableCodec(table s00.TunnelInformationExtIEsValueExtensionTable) s12.TunnelInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeTunnelInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.TunnelInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.TunnelInformationExtIEsExtFieldValueCodec {
		sealed := s12.TunnelInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TunnelInformationExtIEsExtField, error) {
			var field s11.TunnelInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TunnelInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TunnelInformationExtIEsExtField, options aper.DecodeState) (s11.TunnelInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TunnelInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func SONInformationReplyExtIEsValueExtensionTableCodec(table s00.SONInformationReplyExtIEsValueExtensionTable, bounds aper.ListBounds) SONInformationReplyExtIEsExtContainerValueCodec {
	if !*s00.BridgeSONInformationReplyExtIEsValueExtensionTableFieldBound(&table) {
		return SONInformationReplyExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return SONInformationReplyExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (SONInformationReplyExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields SONInformationReplyExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field SONInformationReplyExtIEsExtField
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
		encode: func(fields SONInformationReplyExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v SONInformationReplyExtIEsExtContainer, options aper.DecodeState) (SONInformationReplyExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v SONInformationReplyExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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
func SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableCodec(table s00.SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTable, bounds aper.ListBounds) SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec {
	if !*s00.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableFieldBound(&table) {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field SourceeNBToTargeteNBTransparentContainerExtIEsExtField
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
		encode: func(fields SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, options aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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
					if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			s33.BridgeTargetRNCIDExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTargetRNCIDExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TargetRNCIDExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s33.BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
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
					if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
func TimeBasedHandoverInformationExtIEsValueExtensionTableCodec(table s00.TimeBasedHandoverInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TimeBasedHandoverInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeTimeBasedHandoverInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TimeBasedHandoverInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TimeBasedHandoverInformationExtIEsExtContainerValueCodec {
		sealed := s11.TimeBasedHandoverInformationExtIEsExtContainerValueCodec{}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TimeBasedHandoverInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TimeBasedHandoverInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TimeBasedHandoverInformationExtIEsExtField
					if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TimeBasedHandoverInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TimeBasedHandoverInformationExtIEsExtContainer, options aper.DecodeState) (s11.TimeBasedHandoverInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TimeBasedHandoverInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TimeSynchronisationInfoExtIEsValueExtensionTableCodec(table s00.TimeSynchronisationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s11.TimeSynchronisationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeTimeSynchronisationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s11.TimeSynchronisationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s11.TimeSynchronisationInfoExtIEsExtContainerValueCodec {
		sealed := s11.TimeSynchronisationInfoExtIEsExtContainerValueCodec{}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s11.TimeSynchronisationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s11.TimeSynchronisationInfoExtIEsExtField
					if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s11.BridgeTimeSynchronisationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s11.TimeSynchronisationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s11.BridgeTimeSynchronisationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtContainer, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s11.BridgeTimeSynchronisationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBDirectInformationTransferIEValueIEFieldTableCodec(table s00.ENBDirectInformationTransferIEValueIETable) s33.ENBDirectInformationTransferIEFieldValueCodec {
	if !*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&table) {
		return s33.ENBDirectInformationTransferIEFieldValueCodec{}
	}
	return func() s33.ENBDirectInformationTransferIEFieldValueCodec {
		sealed := s33.ENBDirectInformationTransferIEFieldValueCodec{}
		*s33.BridgeENBDirectInformationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.ENBDirectInformationTransferIEField, error) {
			var field s33.ENBDirectInformationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s33.BridgeENBDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s33.BridgeENBDirectInformationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s33.ENBDirectInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s33.BridgeENBDirectInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s33.BridgeENBDirectInformationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s33.ENBDirectInformationTransferIEField, options aper.DecodeState) (s33.ENBDirectInformationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s33.BridgeENBDirectInformationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s33.ENBDirectInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeENBDirectInformationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverRequiredIEValueIEFieldTableCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEFieldValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return HandoverRequiredIEFieldValueCodec{}
	}
	return HandoverRequiredIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEField, error) {
		var field HandoverRequiredIEField
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
		BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
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
func MMEDirectInformationTransferIEValueIEFieldTableCodec(table s00.MMEDirectInformationTransferIEValueIETable) s33.MMEDirectInformationTransferIEFieldValueCodec {
	if !*s00.BridgeMMEDirectInformationTransferIEValueIETableFieldBound(&table) {
		return s33.MMEDirectInformationTransferIEFieldValueCodec{}
	}
	return func() s33.MMEDirectInformationTransferIEFieldValueCodec {
		sealed := s33.MMEDirectInformationTransferIEFieldValueCodec{}
		*s33.BridgeMMEDirectInformationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.MMEDirectInformationTransferIEField, error) {
			var field s33.MMEDirectInformationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s33.BridgeMMEDirectInformationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s33.MMEDirectInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s33.BridgeMMEDirectInformationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s33.MMEDirectInformationTransferIEField, options aper.DecodeState) (s33.MMEDirectInformationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s33.BridgeMMEDirectInformationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s33.MMEDirectInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeMMEDirectInformationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TraceFailureIndicationIEValueIEFieldTableCodec(table s00.TraceFailureIndicationIEValueIETable) s20.TraceFailureIndicationIEFieldValueCodec {
	if !*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&table) {
		return s20.TraceFailureIndicationIEFieldValueCodec{}
	}
	return func() s20.TraceFailureIndicationIEFieldValueCodec {
		sealed := s20.TraceFailureIndicationIEFieldValueCodec{}
		*s20.BridgeTraceFailureIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.TraceFailureIndicationIEField, error) {
			var field s20.TraceFailureIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s20.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s20.BridgeTraceFailureIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s20.TraceFailureIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s20.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s20.BridgeTraceFailureIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s20.TraceFailureIndicationIEField, options aper.DecodeState) (s20.TraceFailureIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s20.BridgeTraceFailureIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s20.TraceFailureIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeTraceFailureIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBDirectInformationTransferIEValueIETableCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) s33.ENBDirectInformationTransferIEContainerValueCodec {
	if !*s00.BridgeENBDirectInformationTransferIEValueIETableFieldBound(&table) {
		return s33.ENBDirectInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s33.ENBDirectInformationTransferIEContainerValueCodec {
		sealed := s33.ENBDirectInformationTransferIEContainerValueCodec{}
		*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.ENBDirectInformationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.ENBDirectInformationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.ENBDirectInformationTransferIEField
					if err := s33.BridgeENBDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		}
		*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s33.ENBDirectInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s33.BridgeENBDirectInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s33.ENBDirectInformationTransferIEContainer, options aper.DecodeState) (s33.ENBDirectInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s33.ENBDirectInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func HandoverRequiredIEValueIETableCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) HandoverRequiredIEContainerValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return HandoverRequiredIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return HandoverRequiredIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields HandoverRequiredIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field HandoverRequiredIEField
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
			s.End(f, &root, false)
			return v, root
		}, compare: func(v HandoverRequiredIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func MMEDirectInformationTransferIEValueIETableCodec(table s00.MMEDirectInformationTransferIEValueIETable, bounds aper.ListBounds) s33.MMEDirectInformationTransferIEContainerValueCodec {
	if !*s00.BridgeMMEDirectInformationTransferIEValueIETableFieldBound(&table) {
		return s33.MMEDirectInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s33.MMEDirectInformationTransferIEContainerValueCodec {
		sealed := s33.MMEDirectInformationTransferIEContainerValueCodec{}
		*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.MMEDirectInformationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.MMEDirectInformationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.MMEDirectInformationTransferIEField
					if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		}
		*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s33.MMEDirectInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s33.MMEDirectInformationTransferIEContainer, options aper.DecodeState) (s33.MMEDirectInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s33.MMEDirectInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TraceFailureIndicationIEValueIETableCodec(table s00.TraceFailureIndicationIEValueIETable, bounds aper.ListBounds) s20.TraceFailureIndicationIEContainerValueCodec {
	if !*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&table) {
		return s20.TraceFailureIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s20.TraceFailureIndicationIEContainerValueCodec {
		sealed := s20.TraceFailureIndicationIEContainerValueCodec{}
		*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.TraceFailureIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s20.TraceFailureIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s20.TraceFailureIndicationIEField
					if err := s20.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		}
		*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s20.TraceFailureIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s20.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s20.TraceFailureIndicationIEContainer, options aper.DecodeState) (s20.TraceFailureIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s20.TraceFailureIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ENBDirectInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable) s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.ENBDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func HandoverRequiredIEValueProtocolErrorIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequiredIEValueProtocolErrorIEContainerList(value), err
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
		f :=
			s.
				Begin()
		BridgeHandoverRequiredIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func MMEDirectInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable) s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.MMEDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func TraceFailureIndicationIEValueProtocolErrorIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable) s20.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s20.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s20.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s20.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s20.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ENBDirectInformationTransferIEValueProtocolIEContainerListCodec(table s00.ENBDirectInformationTransferIEValueIETable, bounds aper.ListBounds) s33.ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := ENBDirectInformationTransferIEValueIETableCodec(table, bounds)
	if *s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s33.ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s33.ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.ENBDirectInformationTransferIEValueProtocolIEContainerList(value), err
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeENBDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.ENBDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeENBDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func HandoverRequiredIEValueProtocolIEContainerListCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) HandoverRequiredIEValueProtocolIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return HandoverRequiredIEValueProtocolIEContainerListValueCodec{}
	}
	return HandoverRequiredIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return HandoverRequiredIEValueProtocolIEContainerList(value), err
	}, encode: func(value HandoverRequiredIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(HandoverRequiredIEContainer(value), fresh, budget)
	}, capture: func(v HandoverRequiredIEValueProtocolIEContainerList, options aper.DecodeState) (HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v HandoverRequiredIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainerList(&v, &s)
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
func MMEDirectInformationTransferIEValueProtocolIEContainerListCodec(table s00.MMEDirectInformationTransferIEValueIETable, bounds aper.ListBounds) s33.MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := MMEDirectInformationTransferIEValueIETableCodec(table, bounds)
	if *s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s33.MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s33.MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec{}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.MMEDirectInformationTransferIEValueProtocolIEContainerList(value), err
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeMMEDirectInformationTransferIEContainerValueCodecFieldEncode(&codec))(s33.MMEDirectInformationTransferIEContainer(value), fresh, budget)
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeMMEDirectInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func TraceFailureIndicationIEValueProtocolIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable, bounds aper.ListBounds) s20.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, bounds)
	if *s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s20.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s20.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s20.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec{}
		*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s20.TraceFailureIndicationIEValueProtocolIEContainerList(value), err
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s20.TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s20.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s20.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s20.TraceFailureIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s20.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s20.TraceFailureIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// eNBDirectInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s33.ENBDirectInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s33.ENBDirectInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(v *s33.ENBDirectInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s33.BridgeENBDirectInformationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s33.BridgeENBDirectInformationTransferIEFieldFieldReplay(v), *s33.BridgeENBDirectInformationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(v *s33.ENBDirectInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s33.BridgeENBDirectInformationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s33.BridgeENBDirectInformationTransferIEFieldFieldReplay(v), *s33.BridgeENBDirectInformationTransferIEFieldFieldWithoutReplay(v))
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
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// mMEDirectInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s33.MMEDirectInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s33.MMEDirectInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(v *s33.MMEDirectInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s33.BridgeMMEDirectInformationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s33.BridgeMMEDirectInformationTransferIEFieldFieldReplay(v), *s33.BridgeMMEDirectInformationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(v *s33.MMEDirectInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s33.BridgeMMEDirectInformationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s33.BridgeMMEDirectInformationTransferIEFieldFieldReplay(v), *s33.BridgeMMEDirectInformationTransferIEFieldFieldWithoutReplay(v))
}

// sONInformationReplyExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) SONInformationReplyExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (SONInformationReplyExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionField(v *SONInformationReplyExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionField(v *SONInformationReplyExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// sourceeNBToTargeteNBTransparentContainerExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (SourceeNBToTargeteNBTransparentContainerExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCaptureS1APProtocolExtensionField(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
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

// targeteNBIDExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TargeteNBIDExtIEsValue].
type TargeteNBIDExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TargeteNBIDExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TargeteNBIDExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
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

// timeBasedHandoverInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TimeBasedHandoverInformationExtIEsValue].
type TimeBasedHandoverInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TimeBasedHandoverInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TimeBasedHandoverInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTimeBasedHandoverInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TimeBasedHandoverInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTimeBasedHandoverInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.TimeBasedHandoverInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTimeBasedHandoverInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// timeSynchronisationInfoExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TimeSynchronisationInfoExtIEsValue].
type TimeSynchronisationInfoExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.TimeSynchronisationInfoExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.TimeSynchronisationInfoExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TimeSynchronisationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTimeSynchronisationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTimeSynchronisationInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeTimeSynchronisationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s11.TimeSynchronisationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTimeSynchronisationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTimeSynchronisationInfoExtIEsExtFieldFieldReplay(v), *s11.BridgeTimeSynchronisationInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// traceFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[TraceFailureIndicationIEValue].
type TraceFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.TraceFailureIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.TraceFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(v *s20.TraceFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s20.BridgeTraceFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s20.BridgeTraceFailureIndicationIEFieldFieldReplay(v), *s20.BridgeTraceFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(v *s20.TraceFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s20.BridgeTraceFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s20.BridgeTraceFailureIndicationIEFieldFieldReplay(v), *s20.BridgeTraceFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s11.TunnelInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTunnelInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s11.BridgeTunnelInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeTunnelInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionField(v *s11.TunnelInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTunnelInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s11.BridgeTunnelInformationExtIEsExtFieldFieldReplay(v), *s11.BridgeTunnelInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// TimeSynchronisationInfoAPERValue is the concrete APERValue[TimeSynchronisationInfo].
type TimeSynchronisationInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   TimeSynchronisationInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeSynchronisationInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeSynchronisationInfoAPERValue) WithoutReplay() TimeSynchronisationInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeBasedHandoverInformationAPERValue is the concrete APERValue[TimeBasedHandoverInformation].
type TimeBasedHandoverInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TimeBasedHandoverInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeBasedHandoverInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeBasedHandoverInformationAPERValue) WithoutReplay() TimeBasedHandoverInformationAPERValue {
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

// TargetRNCIDAPERValue is the concrete APERValue[TargetRNCID].
type TargetRNCIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s33.TargetRNCID

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

// TraceFailureIndicationAPERValue is the concrete APERValue[TraceFailureIndication].
type TraceFailureIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TraceFailureIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceFailureIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceFailureIndicationAPERValue) WithoutReplay() TraceFailureIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationReplyExtIEsIEField is the concrete ProtocolIEField[SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SONInformationReplyExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReplyExtIEsIEField) WithoutReplay() SONInformationReplyExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONInformationReplyExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONInformationReplyExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *SONInformationReplyExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReplyExtIEsIEField{}
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
	var zero SONInformationReplyExtIEsValue

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

// SONInformationReplyExtIEsIEContainer is the concrete ProtocolIEContainer[SONInformationReplyExtIEsValue].
type SONInformationReplyExtIEsIEContainer []SONInformationReplyExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSONInformationReplyExtIEsValueValidateS1APIEContainer(fields SONInformationReplyExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// SourceeNBToTargeteNBTransparentContainerExtIEsIEField is the concrete ProtocolIEField[SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SourceeNBToTargeteNBTransparentContainerExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceeNBToTargeteNBTransparentContainerExtIEsIEField) WithoutReplay() SourceeNBToTargeteNBTransparentContainerExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SourceeNBToTargeteNBTransparentContainerExtIEsIEField{}
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
	var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue

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

// SourceeNBToTargeteNBTransparentContainerExtIEsIEContainer is the concrete ProtocolIEContainer[SourceeNBToTargeteNBTransparentContainerExtIEsValue].
type SourceeNBToTargeteNBTransparentContainerExtIEsIEContainer []SourceeNBToTargeteNBTransparentContainerExtIEsIEField

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APIEContainer(fields SourceeNBToTargeteNBTransparentContainerExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeTargeteNBIDExtIEsValueValidateS1APIEContainer(fields s11.TargeteNBIDExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTargeteNBIDExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTargeteNBIDExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTargeteNBIDExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APIEContainer(fields s11.TimeBasedHandoverInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTimeBasedHandoverInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTimeBasedHandoverInformationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTimeBasedHandoverInformationExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeTimeSynchronisationInfoExtIEsValueValidateS1APIEContainer(fields s11.TimeSynchronisationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeTimeSynchronisationInfoExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeTimeSynchronisationInfoExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeTimeSynchronisationInfoExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeENBDirectInformationTransferIEValueCaptureS1APERABIEContainerList(v *s33.ENBDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBDirectInformationTransferIEValueCompareS1APERABIEContainerList(v *s33.ENBDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// HandoverRequiredIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueERABIEContainerList is the concrete ERABIEContainerList[HandoverRequiredIEValue].
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
func BridgeMMEDirectInformationTransferIEValueCaptureS1APERABIEContainerList(v *s33.MMEDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEDirectInformationTransferIEValueCompareS1APERABIEContainerList(v *s33.MMEDirectInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCaptureS1APERABIEContainerList(v *s20.TraceFailureIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APERABIEContainerList(v *s20.TraceFailureIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SONInformationReplyExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[SONInformationReplyExtIEsValue]].
type SONInformationReplyExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationReplyExtIEsExtField, error)
	encode  func(SONInformationReplyExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationReplyExtIEsExtField, aper.DecodeState) (SONInformationReplyExtIEsExtField, aper.Snapshot)
	compare func(SONInformationReplyExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationReplyExtIEsExtFieldValueCodec) New(value SONInformationReplyExtIEsExtField) (SONInformationReplyExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SONInformationReplyExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReplyExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationReplyExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationReplyExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationReplyExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationReplyExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationReplyExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationReplyExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationReplyExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationReplyExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationReplyExtIEsExtFieldValueCodec) EncodeAPER(value SONInformationReplyExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONInformationReplyExtIEsExtFieldValueCodec) encodeBudgetValue(value SONInformationReplyExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationReplyExtIEsExtFieldValueCodec) encodeChanged(value SONInformationReplyExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[ProtocolExtensionField[SourceeNBToTargeteNBTransparentContainerExtIEsValue]].
type SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error)
	encode  func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.Snapshot)
	compare func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) New(value SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) EncodeAPER(value SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) encodeBudgetValue(value SourceeNBToTargeteNBTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) encodeChanged(value SourceeNBToTargeteNBTransparentContainerExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationReplyExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[SONInformationReplyExtIEsValue]].
type SONInformationReplyExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationReplyExtIEsExtContainer, error)
	encode  func(SONInformationReplyExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationReplyExtIEsExtContainer, aper.DecodeState) (SONInformationReplyExtIEsExtContainer, aper.Snapshot)
	compare func(SONInformationReplyExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationReplyExtIEsExtContainerValueCodec) New(value SONInformationReplyExtIEsExtContainer) (SONInformationReplyExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SONInformationReplyExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReplyExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationReplyExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationReplyExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationReplyExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationReplyExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationReplyExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationReplyExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationReplyExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationReplyExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationReplyExtIEsExtContainerValueCodec) EncodeAPER(value SONInformationReplyExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONInformationReplyExtIEsExtContainerValueCodec) encodeBudgetValue(value SONInformationReplyExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationReplyExtIEsExtContainerValueCodec) encodeChanged(value SONInformationReplyExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec is the concrete ValueCodec[ProtocolExtensionContainer[SourceeNBToTargeteNBTransparentContainerExtIEsValue]].
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

// HandoverRequiredIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[HandoverRequiredIEValue]].
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

// HandoverRequiredIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[HandoverRequiredIEValue]].
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
func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s33.ENBDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[HandoverRequiredIEValue].
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
func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s33.MMEDirectInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s20.TraceFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(v *s33.ENBDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// HandoverRequiredIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[HandoverRequiredIEValue].
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
func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEContainerList(v *s33.MMEDirectInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainerList(v *s20.TraceFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainerList(v *s20.TraceFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s33.ENBDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *s33.ENBDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeENBDirectInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequiredIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[HandoverRequiredIEValue].
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
func BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s33.MMEDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *s33.MMEDirectInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeMMEDirectInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s20.TraceFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIESingleContainer(v *s20.TraceFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// SONInformationReplyExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[SONInformationReplyExtIEsValue]].
type SONInformationReplyExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationReplyExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationReplyExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReplyExtIEsExtFieldAPERValue) WithoutReplay() SONInformationReplyExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldAPERValue is the concrete APERValue[ProtocolExtensionField[SourceeNBToTargeteNBTransparentContainerExtIEsValue]].
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

// SONInformationReplyExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[SONInformationReplyExtIEsValue]].
type SONInformationReplyExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONInformationReplyExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationReplyExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReplyExtIEsExtContainerAPERValue) WithoutReplay() SONInformationReplyExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue is the concrete APERValue[ProtocolExtensionContainer[SourceeNBToTargeteNBTransparentContainerExtIEsValue]].
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

// HandoverRequiredIEFieldAPERValue is the concrete APERValue[ProtocolIEField[HandoverRequiredIEValue]].
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

// HandoverRequiredIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[HandoverRequiredIEValue]].
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

// HandoverRequiredIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[HandoverRequiredIEValue]].
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
func BridgeCaptureS1APSONInformationReplyExtIEsValue(v *SONInformationReplyExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(149):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSynchronisationInfo == nil)
				if v.rowTimeSynchronisationInfo != nil {
					BridgeCaptureS1APTimeSynchronisationInfo(v.rowTimeSynchronisationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(208):
			{
				f := s.Begin()
				s.Bool(v.rowMutingPatternInformation == nil)
				if v.rowMutingPatternInformation != nil {
					s19.BridgeCaptureS1APMutingPatternInformation(v.rowMutingPatternInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationReplyExtIEsValue) captureSemantics(s aper.SemanticCapture) SONInformationReplyExtIEsValue {
	BridgeCaptureS1APSONInformationReplyExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APSONInformationReplyExtIEsValue(v *SONInformationReplyExtIEsValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(149):
			{
				f := s.Begin()
				s.Bool(v.rowTimeSynchronisationInfo == nil)
				if v.rowTimeSynchronisationInfo != nil {
					BridgeCompareS1APTimeSynchronisationInfo(v.rowTimeSynchronisationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(208):
			{
				f := s.Begin()
				s.Bool(v.rowMutingPatternInformation == nil)
				if v.rowMutingPatternInformation != nil {
					s19.BridgeCompareS1APMutingPatternInformation(v.rowMutingPatternInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONInformationReplyExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSONInformationReplyExtIEsValue(&v, &s)
	return s
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
					s19.BridgeCaptureS1APContextatSource(v.rowContextatSource, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(311):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemMeasurementConfiguration == nil)
				if v.rowIntersystemMeasurementConfiguration != nil {
					s24.BridgeCaptureS1APIntersystemMeasurementConfiguration(v.rowIntersystemMeasurementConfiguration, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(312):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeID == nil)
				if v.rowSourceNodeID != nil {
					s30.BridgeCaptureS1APSourceNodeID(v.rowSourceNodeID, s)
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
					s19.BridgeCaptureS1APGlobalRANNODEID(v.rowSourceSNID, s)
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
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s06.BridgeCompareS1APS1APIEsMobilityInformation(v.rowMobilityInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(194):
			{
				f := s.Begin()
				s.Bool(v.rowUEHistoryInformationFromTheUE == nil)
				if v.rowUEHistoryInformationFromTheUE != nil {
					s07.BridgeCompareS1APUEHistoryInformationFromTheUE(v.rowUEHistoryInformationFromTheUE, s)
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
					s19.BridgeCompareS1APContextatSource(v.rowContextatSource, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(311):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemMeasurementConfiguration == nil)
				if v.rowIntersystemMeasurementConfiguration != nil {
					s24.BridgeCompareS1APIntersystemMeasurementConfiguration(v.rowIntersystemMeasurementConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(312):
			{
				f := s.Begin()
				s.Bool(v.rowSourceNodeID == nil)
				if v.rowSourceNodeID != nil {
					s30.BridgeCompareS1APSourceNodeID(v.rowSourceNodeID, s)
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
					s19.BridgeCompareS1APGlobalRANNODEID(v.rowSourceSNID, s)
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
				s33.BridgeCaptureS1APTargetRNCID(v.TargetRNCID, s)
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
				s33.BridgeCaptureS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
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
				s33.BridgeCompareS1APTargetRNCID(v.TargetRNCID, s)
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
				s33.BridgeCompareS1APTargetNgRanNodeID(v.TargetgNgRanNodeID, s)
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
	s18.BridgeCaptureS1APGlobalENBID(&v.GlobalENBID, s)
	s31.BridgeCaptureS1APTAI(&v.SelectedTAI, s)
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
	s31.BridgeCompareS1APTAI(&v.SelectedTAI, s)
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
func BridgeCaptureS1APTimeSynchronisationInfo(v *TimeSynchronisationInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APStratumLevel(&v.StratumLevel, s)
	s00.BridgeCaptureS1APSynchronisationStatus(&v.SynchronisationStatus, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTimeSynchronisationInfo(v *TimeSynchronisationInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APStratumLevel(&v.StratumLevel, s)
	s07.BridgeCompareS1APSynchronisationStatus(&v.SynchronisationStatus, s)
	s.Bool(v.IEExtensions == nil)
	BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTraceFailureIndication(v *TraceFailureIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTraceFailureIndication(v *TraceFailureIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTunnelInformation(v *TunnelInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	{
		f := s.Begin()
		s.Bool(v.UDPPortNumber == nil)
		if v.UDPPortNumber != nil {
			s00.BridgeCaptureS1APPortNumber(v.UDPPortNumber, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTunnelInformation(v *TunnelInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTransportLayerAddress(&v.TransportLayerAddress, s)
	{
		f := s.Begin()
		s.Bool(v.UDPPortNumber == nil)
		if v.UDPPortNumber != nil {
			s02.BridgeCompareS1APPortNumber(v.UDPPortNumber, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// NewRIMRoutingAddressGERANCellID creates a RIMRoutingAddress with the gERAN-Cell-ID alternative.
func BridgeNewRIMRoutingAddressGERANCellIDLegacy(v s18.GERANCellID) s33.RIMRoutingAddress {
	return s33.RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceGERANCellID,
		GERANCellID: &v,
	}
}

// NewRIMRoutingAddressTargetRNCID creates a RIMRoutingAddress with the targetRNC-ID alternative.
func BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v s33.TargetRNCID) s33.RIMRoutingAddress {
	return s33.RIMRoutingAddress{
		Choice:      s00.RIMRoutingAddressChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewRIMRoutingAddressEHRPDSectorID creates a RIMRoutingAddress with the eHRPD-Sector-ID alternative.
func BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v []byte) s33.RIMRoutingAddress {
	return s33.RIMRoutingAddress{
		Choice:        s00.RIMRoutingAddressChoiceEHRPDSectorID,
		EHRPDSectorID: v,
	}
}

// TimeSynchronisationInfo represents the ASN.1 type TimeSynchronisationInfo (SEQUENCE).
type TimeSynchronisationInfo struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	StratumLevel          s00.StratumLevel                              `asn1:"tag:0,context,implicit"`
	SynchronisationStatus s00.SynchronisationStatus                     `asn1:"tag:1,context,implicit"`
	IEExtensions          s11.TimeSynchronisationInfoExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                          `asn1:"-" json:"-"`
	extCount              int64                                         `asn1:"-" json:"-"`
	extPresent            []bool                                        `asn1:"-" json:"-"`
	extData               [][]byte                                      `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
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
	TargetRNCID        *s33.TargetRNCID       `json:"TargetRNCID,omitempty"`
	CGI                *s14.CGI               `json:"CGI,omitempty"`
	TargetgNgRanNodeID *s33.TargetNgRanNodeID `json:"TargetgNgRanNodeID,omitempty"`
}

// NewTargetIDTargeteNBID creates a TargetID with the targeteNB-ID alternative.
func BridgeNewTargetIDTargeteNBIDLegacy(v TargeteNBID) TargetID {
	return TargetID{
		Choice:      s00.TargetIDChoiceTargeteNBID,
		TargeteNBID: &v,
	}
}

// NewTargetIDTargetRNCID creates a TargetID with the targetRNC-ID alternative.
func BridgeNewTargetIDTargetRNCIDLegacy(v s33.TargetRNCID) TargetID {
	return TargetID{
		Choice:      s00.TargetIDChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewTargetIDCGI creates a TargetID with the cGI alternative.
func BridgeNewTargetIDCGILegacy(v s14.CGI) TargetID {
	return TargetID{
		Choice: s00.TargetIDChoiceCGI,
		CGI:    &v,
	}
}

// NewTargetIDTargetgNgRanNodeID creates a TargetID with the targetgNgRanNode-ID alternative.
func BridgeNewTargetIDTargetgNgRanNodeIDLegacy(v s33.TargetNgRanNodeID) TargetID {
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
	GlobalENBID       s18.GlobalENBID                   `asn1:"tag:0,context,implicit"`
	SelectedTAI       s31.TAI                           `asn1:"tag:1,context,implicit"`
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
	IEExtensions      s11.TimeBasedHandoverInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// TunnelInformation represents the ASN.1 type TunnelInformation (SEQUENCE).
type TunnelInformation struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	received              bool
	withoutReplay         bool
	receivedAbsolute      bool
	receivedBytes         aper.WireSpan
	receivedLocation      aper.Location
	TransportLayerAddress s00.TransportLayerAddress               `asn1:"tag:0,context,implicit"`
	UDPPortNumber         *s00.PortNumber                         `asn1:"tag:1,context,implicit,optional" json:"UDPPortNumber,omitempty"`
	IEExtensions          s11.TunnelInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef     bool                                    `asn1:"-" json:"-"`
	extCount              int64                                   `asn1:"-" json:"-"`
	extPresent            []bool                                  `asn1:"-" json:"-"`
	extData               [][]byte                                `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// MarshalAPER encodes TimeSynchronisationInfo to APER format.
func (v *TimeSynchronisationInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TimeSynchronisationInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.StratumLevel, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true); err != nil {
		return fmt.Errorf("encoding stratumLevel: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.SynchronisationStatus), 2, true); err != nil {
		return fmt.Errorf("encoding synchronisationStatus: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TimeSynchronisationInfo from APER format.
func (v *TimeSynchronisationInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TimeSynchronisationInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TimeSynchronisationInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TimeSynchronisationInfo")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TimeSynchronisationInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "TimeSynchronisationInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeSynchronisationInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TimeSynchronisationInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeSynchronisationInfo{}
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
	val_stratumlevel, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound9, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "StratumLevel")
	}
	v.StratumLevel = val_stratumlevel
	val_synchronisationstatus, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SynchronisationStatus"})
	if err != nil {
		return runtime.WrapDecodePath(err, "SynchronisationStatus")
	}
	v.SynchronisationStatus = s00.SynchronisationStatus(val_synchronisationstatus)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TimeSynchronisationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TimeSynchronisationInfoExtIEsExtField
				if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s33.BridgeTargetNgRanNodeIDMethodMarshalAPERTo(v.TargetgNgRanNodeID, inner, len(fresh) != 0 && fresh[0]); err != nil {
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
		if err := s33.BridgeTargetRNCIDMethodMarshalAPERTo(v.TargetRNCID, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			recoveryMark_targetgngrannodeid := inner.RecoveryComponent("TargetgNgRanNodeID")
			var dec_targetgngrannodeid s33.TargetNgRanNodeID
			if err := s33.BridgeTargetNgRanNodeIDMethodUnmarshalAPERFrom(&dec_targetgngrannodeid, inner); err != nil {
				return runtime.WrapDecodePath(err, "TargetgNgRanNodeID")
			}
			if err := aper.ChargeValue(inner, dec_targetgngrannodeid); err != nil {
				return err
			}
			v.TargetgNgRanNodeID = &dec_targetgngrannodeid
			inner.LeaveComponent(recoveryMark_targetgngrannodeid)
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
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
		var dec_targetrncid s33.TargetRNCID
		if err := s33.BridgeTargetRNCIDMethodUnmarshalAPERFrom(&dec_targetrncid, bb); err != nil {
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
	if err := s31.BridgeTAIMethodMarshalAPERTo(&v.SelectedTAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&v.SelectedTAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "SelectedTAI")
	}
	bb.LeaveComponent(toleranceMark_selectedtai)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TargeteNBIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargeteNBIDExtIEsExtField
				if err := s11.BridgeTargeteNBIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.HOWindowStart), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(1048575), false); err != nil {
		return fmt.Errorf("encoding hOWindowStart: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.HOWindowDuration), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(6000), false); err != nil {
		return fmt.Errorf("encoding hOWindowDuration: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TimeBasedHandoverInformation from APER format.
func (v *TimeBasedHandoverInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TimeBasedHandoverInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TimeBasedHandoverInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TimeBasedHandoverInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TimeBasedHandoverInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TimeBasedHandoverInformation{}
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
	val_howindowstart, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(1048575), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HOWindowStart")
	}
	v.HOWindowStart = s00.HandoverWindowStart(val_howindowstart)
	val_howindowduration, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(6000), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "HOWindowDuration")
	}
	v.HOWindowDuration = s00.HandoverWindowDuration(val_howindowduration)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TimeBasedHandoverInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TimeBasedHandoverInformationExtIEsExtField
				if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes TunnelInformation to APER format.
func (v *TunnelInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TunnelInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.UDPPortNumber != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.TransportLayerAddress.Bytes, v.TransportLayerAddress.BitLength, 1, 160, true, true); err != nil {
		return fmt.Errorf("encoding transportLayerAddress: %w", err)
	}
	if v.UDPPortNumber != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.UDPPortNumber), 2, 2, true); err != nil {
			return fmt.Errorf("encoding uDP-Port-Number: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TunnelInformation from APER format.
func (v *TunnelInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TunnelInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TunnelInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TunnelInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TunnelInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "TunnelInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "TunnelInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TunnelInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TunnelInformation{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_udpportnumber, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	bsBytes_transportlayeraddress, bsBitLen_transportlayeraddress, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "TransportLayerAddress")
	}
	v.TransportLayerAddress = runtime.BitString{Bytes: bsBytes_transportlayeraddress, BitLength: bsBitLen_transportlayeraddress}
	if opt_udpportnumber {
		val_udpportnumber, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UDPPortNumber")
		}
		tmp_udpportnumber := s00.PortNumber(val_udpportnumber)
		if err := aper.ChargeValue(bb, tmp_udpportnumber); err != nil {
			return err
		}
		v.UDPPortNumber = &tmp_udpportnumber
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TunnelInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TunnelInformationExtIEsExtField
				if err := s11.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TimeBasedHandoverInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TimeBasedHandoverInformation", v.receivedLocation, v.perPadding)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TimeSynchronisationInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TimeSynchronisationInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TimeSynchronisationInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TimeSynchronisationInfo) WithoutReplay() TimeSynchronisationInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TimeSynchronisationInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TunnelInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TunnelInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TunnelInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TunnelInformation) WithoutReplay() TunnelInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TunnelInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
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

// Extensions returns owned unknown sequence additions.
func (v *TimeSynchronisationInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TimeSynchronisationInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TimeSynchronisationInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TimeSynchronisationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TimeSynchronisationInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TimeSynchronisationInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TimeSynchronisationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TunnelInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TunnelInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TunnelInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TunnelInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TunnelInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TunnelInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TunnelInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TimeSynchronisationInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TimeSynchronisationInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TimeSynchronisationInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TimeSynchronisationInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTimeSynchronisationInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TimeSynchronisationInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TimeSynchronisationInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TimeSynchronisationInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TimeSynchronisationInfo")
}
func (v *TimeSynchronisationInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TimeSynchronisationInfo")
}
func (v *TimeSynchronisationInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTimeSynchronisationInfo(v, &s)
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
func (v *TimeSynchronisationInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TimeSynchronisationInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TunnelInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TunnelInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TunnelInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TunnelInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTunnelInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TunnelInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TunnelInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TunnelInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TunnelInformation")
}
func (v *TunnelInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TunnelInformation")
}
func (v *TunnelInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTunnelInformation(v, &s)
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
func (v *TunnelInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TunnelInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TimeSynchronisationInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TimeSynchronisationInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TimeSynchronisationInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTimeSynchronisationInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TimeSynchronisationInfo{}
		return report, aper.OperationError(err, "TimeSynchronisationInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TimeSynchronisationInfo")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TunnelInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TunnelInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TunnelInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTunnelInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TunnelInformation{}
		return report, aper.OperationError(err, "TunnelInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TunnelInformation")
}

// NewRIMRoutingAddressGERANCellID constructs a checked complete value.
func NewRIMRoutingAddressGERANCellID(v s18.GERANCellID, options ...aper.BuildOption) (s33.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	value := BridgeNewRIMRoutingAddressGERANCellIDLegacy(v)
	if _, err := s33.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressGERANCellID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressGERANCellID")
}

// NewRIMRoutingAddressTargetRNCID constructs a checked complete value.
func NewRIMRoutingAddressTargetRNCID(v s33.TargetRNCID, options ...aper.BuildOption) (s33.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	value := BridgeNewRIMRoutingAddressTargetRNCIDLegacy(v)
	if _, err := s33.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressTargetRNCID")
	}
	return value, aper.OperationError(nil, "RIMRoutingAddressTargetRNCID")
}

// NewRIMRoutingAddressEHRPDSectorID constructs a checked complete value.
func NewRIMRoutingAddressEHRPDSectorID(v []byte, options ...aper.BuildOption) (s33.RIMRoutingAddress, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
	}
	value := BridgeNewRIMRoutingAddressEHRPDSectorIDLegacy(v)
	if _, err := s33.BridgeRIMRoutingAddressMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s33.RIMRoutingAddress{}, aper.OperationError(err, "RIMRoutingAddressEHRPDSectorID")
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
func NewTargetIDTargetRNCID(v s33.TargetRNCID, options ...aper.BuildOption) (TargetID, error) {
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
func NewTargetIDCGI(v s14.CGI, options ...aper.BuildOption) (TargetID, error) {
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
func NewTargetIDTargetgNgRanNodeID(v s33.TargetNgRanNodeID, options ...aper.BuildOption) (TargetID, error) {
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

// TraceFailureIndication represents the ASN.1 type TraceFailureIndication (SEQUENCE).
type TraceFailureIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s20.TraceFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
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
	ProtocolIEs      s33.ENBDirectInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// NewInterSystemInformationTransferTypeRIMTransfer creates a InterSystemInformationTransferType with the rIMTransfer alternative.
func BridgeNewInterSystemInformationTransferTypeRIMTransferLegacy(v s33.RIMTransfer) s33.InterSystemInformationTransferType {
	return s33.InterSystemInformationTransferType{
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
	ProtocolIEs      s33.MMEDirectInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
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

// UnmarshalAPER decodes HandoverRequired from APER format.
func (v *HandoverRequired) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverRequired with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverRequired) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRequired")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequired")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverRequired) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequired{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(HandoverRequiredIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem HandoverRequiredIEField
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

// MarshalAPER encodes TraceFailureIndication to APER format.
func (v *TraceFailureIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TraceFailureIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s20.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes TraceFailureIndication from APER format.
func (v *TraceFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TraceFailureIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TraceFailureIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TraceFailureIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceFailureIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "TraceFailureIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceFailureIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TraceFailureIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceFailureIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s20.TraceFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s20.TraceFailureIndicationIEField
			if err := s20.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s33.BridgeENBDirectInformationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s33.ENBDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s33.ENBDirectInformationTransferIEField
			if err := s33.BridgeENBDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s33.MMEDirectInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s33.MMEDirectInformationTransferIEField
			if err := s33.BridgeMMEDirectInformationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *HandoverRequired) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverRequired", v.receivedLocation, v.perPadding)
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
func (v *TraceFailureIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TraceFailureIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TraceFailureIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TraceFailureIndication) WithoutReplay() TraceFailureIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TraceFailureIndication
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

// Extensions returns owned unknown sequence additions.
func (v *TraceFailureIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TraceFailureIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceFailureIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TraceFailureIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceFailureIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceFailureIndication.Extensions[%d]", index))
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
func (v *TraceFailureIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TraceFailureIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TraceFailureIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TraceFailureIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTraceFailureIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TraceFailureIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TraceFailureIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TraceFailureIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TraceFailureIndication")
}
func (v *TraceFailureIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TraceFailureIndication")
}
func (v *TraceFailureIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTraceFailureIndication(v, &s)
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
func (v *TraceFailureIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TraceFailureIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TraceFailureIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TraceFailureIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TraceFailureIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTraceFailureIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TraceFailureIndication{}
		return report, aper.OperationError(err, "TraceFailureIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TraceFailureIndication")
}

// NewInterSystemInformationTransferTypeRIMTransfer constructs a checked complete value.
func NewInterSystemInformationTransferTypeRIMTransfer(v s33.RIMTransfer, options ...aper.BuildOption) (s33.InterSystemInformationTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s33.InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	value := BridgeNewInterSystemInformationTransferTypeRIMTransferLegacy(v)
	if _, err := s33.BridgeInterSystemInformationTransferTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s33.InterSystemInformationTransferType{}, aper.OperationError(err, "InterSystemInformationTransferTypeRIMTransfer")
	}
	return value, aper.OperationError(nil, "InterSystemInformationTransferTypeRIMTransfer")
}

type SONInformationReplyExtIEsValue struct {
	id                          s00.ProtocolIEID
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      aper.OpaqueOpenType
	isOpaque                    bool
	rowTimeSynchronisationInfo  *TimeSynchronisationInfo
	rowMutingPatternInformation *s19.MutingPatternInformation
}

func (v SONInformationReplyExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(149):
		return v.rowTimeSynchronisationInfo != nil
	case s00.ProtocolIEID(208):
		return v.rowMutingPatternInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SONInformationReplyExtIEsValue and reports whether the opaque alternative is selected.
func (v *SONInformationReplyExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SONInformationReplyExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReply-ExtIEs"}}
}
func (SONInformationReplyExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(149):
		return aper.UnknownSelector
	case s00.ProtocolIEID(208):
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

// AsTimeSynchronisationInfo returns the selected TimeSynchronisationInfo value of SONInformationReplyExtIEsValue and reports whether that alternative is active.
func (v *SONInformationReplyExtIEsValue) AsTimeSynchronisationInfo() (*TimeSynchronisationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(149) || v.rowTimeSynchronisationInfo == nil {
		return nil, false
	}
	return v.rowTimeSynchronisationInfo, true
}

// AsMutingPatternInformation returns the selected MutingPatternInformation value of SONInformationReplyExtIEsValue and reports whether that alternative is active.
func (v *SONInformationReplyExtIEsValue) AsMutingPatternInformation() (*s19.MutingPatternInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(208) || v.rowMutingPatternInformation == nil {
		return nil, false
	}
	return v.rowMutingPatternInformation, true
}
func (v SONInformationReplyExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SONInformationReplyExtIEsValue, error) {
	out := SONInformationReplyExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(149):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TimeSynchronisationInfo
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TimeSynchronisationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TimeSynchronisationInfo")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowTimeSynchronisationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(208):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.MutingPatternInformation
		child := scope
		if err := s19.BridgeMutingPatternInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "MutingPatternInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MutingPatternInformation")
		if err != nil {
			return out, err
		}
		*s19.BridgeMutingPatternInformationFieldPerPadding(&value) = padding
		*s19.BridgeMutingPatternInformationFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeMutingPatternInformationFieldReceivedBytes(&value))
		*s19.BridgeMutingPatternInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowMutingPatternInformation = &value
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
func (v SONInformationReplyExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v SONInformationReplyExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(149):
		if v.rowTimeSynchronisationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "SONInformationReply-ExtIEs.id-Time-Synchronisation-Info:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowTimeSynchronisationInfo.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(208):
		if v.rowMutingPatternInformation == nil {
			return nil, fmt.Errorf("%s missing value", "SONInformationReply-ExtIEs.id-Muting-Pattern-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeMutingPatternInformationMethodMarshalAPERBudget(v.rowMutingPatternInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SONInformationReplyExtIEsValue:", v.id)
	}
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
	rowContextatSource                     *s19.ContextatSource
	rowIntersystemMeasurementConfiguration *s24.IntersystemMeasurementConfiguration
	rowSourceNodeID                        *s30.SourceNodeID
	rowEmergencyIndicator                  *s00.EmergencyIndicator
	rowUEContextReferenceatSourceeNB       *s00.ENBUES1APID
	rowSourceSNID                          *s19.GlobalRANNODEID
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
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsContextatSource() (*s19.ContextatSource, bool) {
	if v == nil || v.id != s00.ProtocolIEID(300) || v.rowContextatSource == nil {
		return nil, false
	}
	return v.rowContextatSource, true
}

// AsIntersystemMeasurementConfiguration returns the selected IntersystemMeasurementConfiguration value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsIntersystemMeasurementConfiguration() (*s24.IntersystemMeasurementConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(311) || v.rowIntersystemMeasurementConfiguration == nil {
		return nil, false
	}
	return v.rowIntersystemMeasurementConfiguration, true
}

// AsSourceNodeID returns the selected SourceNodeID value of SourceeNBToTargeteNBTransparentContainerExtIEsValue and reports whether that alternative is active.
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsSourceNodeID() (*s30.SourceNodeID, bool) {
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
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsSourceSNID() (*s19.GlobalRANNODEID, bool) {
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
		var value s19.ContextatSource
		child := scope
		if err := s19.BridgeContextatSourceMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ContextatSource:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ContextatSource")
		if err != nil {
			return out, err
		}
		*s19.BridgeContextatSourceFieldPerPadding(&value) = padding
		*s19.BridgeContextatSourceFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeContextatSourceFieldReceivedBytes(&value))
		*s19.BridgeContextatSourceFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowContextatSource = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(311):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s24.IntersystemMeasurementConfiguration
		child := scope
		if err := s24.BridgeIntersystemMeasurementConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "IntersystemMeasurementConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "IntersystemMeasurementConfiguration")
		if err != nil {
			return out, err
		}
		*s24.BridgeIntersystemMeasurementConfigurationFieldPerPadding(&value) = padding
		*s24.BridgeIntersystemMeasurementConfigurationFieldReceived(&value) = true
		raw.RetainContents(s24.BridgeIntersystemMeasurementConfigurationFieldReceivedBytes(&value))
		*s24.BridgeIntersystemMeasurementConfigurationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowIntersystemMeasurementConfiguration = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(312):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s30.SourceNodeID
		child := scope
		if err := s30.BridgeSourceNodeIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceNodeID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SourceNodeID")
		if err != nil {
			return out, err
		}
		*s30.BridgeSourceNodeIDFieldPerPadding(&value) = padding.Padding()
		*s30.BridgeSourceNodeIDFieldReceived(&value) = true
		raw.RetainContents(s30.BridgeSourceNodeIDFieldReceivedBytes(&value))
		*s30.BridgeSourceNodeIDFieldReceivedLocation(&value) = raw.ContentLocation()
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
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
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
		var value s19.GlobalRANNODEID
		child := scope
		if err := s19.BridgeGlobalRANNODEIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceSNID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GlobalRANNODEID")
		if err != nil {
			return out, err
		}
		*s19.BridgeGlobalRANNODEIDFieldPerPadding(&value) = padding.Padding()
		*s19.BridgeGlobalRANNODEIDFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeGlobalRANNODEIDFieldReceivedBytes(&value))
		*s19.BridgeGlobalRANNODEIDFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s19.BridgeContextatSourceMethodMarshalAPERBudget(v.rowContextatSource, budget, fresh)
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
		candidate, err := s24.BridgeIntersystemMeasurementConfigurationMethodMarshalAPERBudget(v.rowIntersystemMeasurementConfiguration, budget, fresh)
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
		candidate, err := s30.BridgeSourceNodeIDMethodMarshalAPERBudget(v.rowSourceNodeID, budget, fresh)
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
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowUEContextReferenceatSourceeNB), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
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
		candidate, err := s19.BridgeGlobalRANNODEIDMethodMarshalAPERBudget(v.rowSourceSNID, budget, fresh)
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

type SONInformationReplyExtIETable struct{}

func SONInformationReplyExtIEs() SONInformationReplyExtIETable {
	return SONInformationReplyExtIETable{}
}

// ID returns the ASN.1 object-set identity of SONInformationReplyExtIETable.
func (SONInformationReplyExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReply-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SONInformationReplyExtIETable.
func (SONInformationReplyExtIETable) Table() s00.SONInformationReplyExtIEsValueExtensionTable {
	return func() s00.SONInformationReplyExtIEsValueExtensionTable {
		sealed := s00.SONInformationReplyExtIEsValueExtensionTable{}
		*s00.BridgeSONInformationReplyExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SONInformationReplyExtIETable) infoTimeSynchronisationInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SONInformationReplyExtIEs().ID(), ID: s00.ProtocolExtensionID(149), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeSynchronisationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReply-ExtIEs", Row: "id-Time-Synchronisation-Info"}}}
}

// TimeSynchronisationInfo returns the typed binding for the TimeSynchronisationInfo row of SONInformationReplyExtIETable.
func (t SONInformationReplyExtIETable) TimeSynchronisationInfo() SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding {
	return SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding{info: t.infoTimeSynchronisationInfo(), codec: TimeSynchronisationInfoValueCodec{path: "TimeSynchronisationInfo",
		decode: func(data []byte, options aper.DecodeState) (TimeSynchronisationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TimeSynchronisationInfo
				return empty, err
			}
			var zero SONInformationReplyExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(149), raw)
			if err != nil {
				var empty TimeSynchronisationInfo
				return empty, err
			}
			value, ok := decoded.AsTimeSynchronisationInfo()
			if !ok {
				var empty TimeSynchronisationInfo
				return empty, fmt.Errorf("binding SONInformationReply-ExtIEs.id-Time-Synchronisation-Info: no selected value")
			}
			return *value, nil
		},
		encode: func(value TimeSynchronisationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONInformationReplyExtIEsValue{id: s00.ProtocolIEID(149), rowTimeSynchronisationInfo: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TimeSynchronisationInfo, options aper.DecodeState) (TimeSynchronisationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APTimeSynchronisationInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}, compare: func(v TimeSynchronisationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTimeSynchronisationInfo(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeSynchronisationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TimeSynchronisationInfo) SONInformationReplyExtIEsValue {
		return SONInformationReplyExtIEsValue{id: s00.ProtocolIEID(149), rowTimeSynchronisationInfo: &value}
	}, get: func(value *SONInformationReplyExtIEsValue) (*TimeSynchronisationInfo, bool) {
		return value.AsTimeSynchronisationInfo()
	}}
}
func (SONInformationReplyExtIETable) infoMutingPatternInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SONInformationReplyExtIEs().ID(), ID: s00.ProtocolExtensionID(208), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MutingPatternInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONInformationReply-ExtIEs", Row: "id-Muting-Pattern-Information"}}}
}

// MutingPatternInformation returns the typed binding for the MutingPatternInformation row of SONInformationReplyExtIETable.
func (t SONInformationReplyExtIETable) MutingPatternInformation() SONInformationReplyExtIEsMutingPatternInformationExtBinding {
	return SONInformationReplyExtIEsMutingPatternInformationExtBinding{info: t.infoMutingPatternInformation(), codec: func() s19.MutingPatternInformationValueCodec {
		sealed := s19.MutingPatternInformationValueCodec{}
		*s19.BridgeMutingPatternInformationValueCodecFieldPath(&sealed) = "MutingPatternInformation"
		*s19.BridgeMutingPatternInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.MutingPatternInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.MutingPatternInformation
				return empty, err
			}
			var zero SONInformationReplyExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(208), raw)
			if err != nil {
				var empty s19.MutingPatternInformation
				return empty, err
			}
			value, ok := decoded.AsMutingPatternInformation()
			if !ok {
				var empty s19.MutingPatternInformation
				return empty, fmt.Errorf("binding SONInformationReply-ExtIEs.id-Muting-Pattern-Information: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeMutingPatternInformationValueCodecFieldEncode(&sealed) = func(value s19.MutingPatternInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONInformationReplyExtIEsValue{id: s00.ProtocolIEID(208), rowMutingPatternInformation: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeMutingPatternInformationValueCodecFieldCapture(&sealed) = func(v s19.MutingPatternInformation, options aper.DecodeState) (s19.MutingPatternInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APMutingPatternInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeMutingPatternInformationValueCodecFieldCompare(&sealed) = func(v s19.MutingPatternInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APMutingPatternInformation(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeMutingPatternInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MutingPatternInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.MutingPatternInformation) SONInformationReplyExtIEsValue {
			return SONInformationReplyExtIEsValue{id: s00.ProtocolIEID(208), rowMutingPatternInformation: &value}
		}, get: func(value *SONInformationReplyExtIEsValue) (*s19.MutingPatternInformation, bool) {
			return value.AsMutingPatternInformation()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SONInformationReplyExtIETable.
func (t SONInformationReplyExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SONInformationReplyExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(149):
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Time-Synchronisation-Info requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(208):
		return SONInformationReplyExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Muting-Pattern-Information requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SONInformationReplyExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SONInformationReplyExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: SONInformationReplyExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type SourceeNBToTargeteNBTransparentContainerExtIETable struct{}

func SourceeNBToTargeteNBTransparentContainerExtIEs() SourceeNBToTargeteNBTransparentContainerExtIETable {
	return SourceeNBToTargeteNBTransparentContainerExtIETable{}
}

// ID returns the ASN.1 object-set identity of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (SourceeNBToTargeteNBTransparentContainerExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SourceeNBToTargeteNBTransparentContainerExtIETable.
func (SourceeNBToTargeteNBTransparentContainerExtIETable) Table() s00.SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTable {
	return func() s00.SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTable {
		sealed := s00.SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTable{}
		*s00.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoMobilityInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(175), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MobilityInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-MobilityInformation"}}}
}

// MobilityInformation returns the typed binding for the MobilityInformation row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) MobilityInformation() SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding{info: t.infoMobilityInformation(), codec: func() s01.S1APIEsMobilityInformationValueCodec {
		sealed := s01.S1APIEsMobilityInformationValueCodec{}
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldPath(&sealed) = "S1APIEsMobilityInformation"
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.S1APIEsMobilityInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.S1APIEsMobilityInformation
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(175), raw)
			if err != nil {
				var empty s00.S1APIEsMobilityInformation
				return empty, err
			}
			value, ok := decoded.AsMobilityInformation()
			if !ok {
				var empty s00.S1APIEsMobilityInformation
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-MobilityInformation: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldEncode(&sealed) = func(value s00.S1APIEsMobilityInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(175), rowMobilityInformation: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldCapture(&sealed) = func(v s00.S1APIEsMobilityInformation, options aper.DecodeState) (s00.S1APIEsMobilityInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APS1APIEsMobilityInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldCompare(&sealed) = func(v s00.S1APIEsMobilityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APS1APIEsMobilityInformation(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeS1APIEsMobilityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:S1APIEsMobilityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.S1APIEsMobilityInformation) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(175), rowMobilityInformation: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.S1APIEsMobilityInformation, bool) {
			return value.AsMobilityInformation()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoUEHistoryInformationFromTheUE() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(194), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-HistoryInformationFromTheUE"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-uE-HistoryInformationFromTheUE"}}}
}

// UEHistoryInformationFromTheUE returns the typed binding for the UEHistoryInformationFromTheUE row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) UEHistoryInformationFromTheUE() SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding{info: t.infoUEHistoryInformationFromTheUE(), codec: func() s02.UEHistoryInformationFromTheUEValueCodec {
		sealed := s02.UEHistoryInformationFromTheUEValueCodec{}
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldPath(&sealed) = "UEHistoryInformationFromTheUE"
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEHistoryInformationFromTheUE, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEHistoryInformationFromTheUE
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(194), raw)
			if err != nil {
				var empty s00.UEHistoryInformationFromTheUE
				return empty, err
			}
			value, ok := decoded.AsUEHistoryInformationFromTheUE()
			if !ok {
				var empty s00.UEHistoryInformationFromTheUE
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-uE-HistoryInformationFromTheUE: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldEncode(&sealed) = func(value s00.UEHistoryInformationFromTheUE, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(194), rowUEHistoryInformationFromTheUE: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldCapture(&sealed) = func(v s00.UEHistoryInformationFromTheUE, options aper.DecodeState) (s00.UEHistoryInformationFromTheUE, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEHistoryInformationFromTheUE(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldCompare(&sealed) = func(v s00.UEHistoryInformationFromTheUE, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s07.BridgeCompareS1APUEHistoryInformationFromTheUE(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUEHistoryInformationFromTheUEValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEHistoryInformationFromTheUE"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEHistoryInformationFromTheUE) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(194), rowUEHistoryInformationFromTheUE: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.UEHistoryInformationFromTheUE, bool) {
			return value.AsUEHistoryInformationFromTheUE()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoIMSvoiceEPSfallbackfrom5G() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(296), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IMSvoiceEPSfallbackfrom5G"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-IMSvoiceEPSfallbackfrom5G"}}}
}

// IMSvoiceEPSfallbackfrom5G returns the typed binding for the IMSvoiceEPSfallbackfrom5G row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) IMSvoiceEPSfallbackfrom5G() SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding{info: t.infoIMSvoiceEPSfallbackfrom5G(), codec: func() s01.IMSvoiceEPSfallbackfrom5GValueCodec {
		sealed := s01.IMSvoiceEPSfallbackfrom5GValueCodec{}
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldPath(&sealed) = "IMSvoiceEPSfallbackfrom5G"
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IMSvoiceEPSfallbackfrom5G, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IMSvoiceEPSfallbackfrom5G
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(296), raw)
			if err != nil {
				var empty s00.IMSvoiceEPSfallbackfrom5G
				return empty, err
			}
			value, ok := decoded.AsIMSvoiceEPSfallbackfrom5G()
			if !ok {
				var empty s00.IMSvoiceEPSfallbackfrom5G
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-IMSvoiceEPSfallbackfrom5G: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldEncode(&sealed) = func(value s00.IMSvoiceEPSfallbackfrom5G, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(296), rowIMSvoiceEPSfallbackfrom5G: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldCapture(&sealed) = func(v s00.IMSvoiceEPSfallbackfrom5G, options aper.DecodeState) (s00.IMSvoiceEPSfallbackfrom5G, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIMSvoiceEPSfallbackfrom5G(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldCompare(&sealed) = func(v s00.IMSvoiceEPSfallbackfrom5G, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIMSvoiceEPSfallbackfrom5G(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IMSvoiceEPSfallbackfrom5G"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IMSvoiceEPSfallbackfrom5G) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(296), rowIMSvoiceEPSfallbackfrom5G: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.IMSvoiceEPSfallbackfrom5G, bool) {
			return value.AsIMSvoiceEPSfallbackfrom5G()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoAdditionalRRMPriorityIndex() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) AdditionalRRMPriorityIndex() SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsAdditionalRRMPriorityIndexExtBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.AdditionalRRMPriorityIndex) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoContextatSource() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(300), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ContextatSource"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-ContextatSource"}}}
}

// ContextatSource returns the typed binding for the ContextatSource row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) ContextatSource() SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding{info: t.infoContextatSource(), codec: func() s19.ContextatSourceValueCodec {
		sealed := s19.ContextatSourceValueCodec{}
		*s19.BridgeContextatSourceValueCodecFieldPath(&sealed) = "ContextatSource"
		*s19.BridgeContextatSourceValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ContextatSource, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.ContextatSource
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(300), raw)
			if err != nil {
				var empty s19.ContextatSource
				return empty, err
			}
			value, ok := decoded.AsContextatSource()
			if !ok {
				var empty s19.ContextatSource
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-ContextatSource: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeContextatSourceValueCodecFieldEncode(&sealed) = func(value s19.ContextatSource, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(300), rowContextatSource: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeContextatSourceValueCodecFieldCapture(&sealed) = func(v s19.ContextatSource, options aper.DecodeState) (s19.ContextatSource, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APContextatSource(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeContextatSourceValueCodecFieldCompare(&sealed) = func(v s19.ContextatSource, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APContextatSource(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeContextatSourceValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ContextatSource"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.ContextatSource) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(300), rowContextatSource: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s19.ContextatSource, bool) {
			return value.AsContextatSource()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoIntersystemMeasurementConfiguration() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(311), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IntersystemMeasurementConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-IntersystemMeasurementConfiguration"}}}
}

// IntersystemMeasurementConfiguration returns the typed binding for the IntersystemMeasurementConfiguration row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) IntersystemMeasurementConfiguration() SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding{info: t.infoIntersystemMeasurementConfiguration(), codec: func() s24.IntersystemMeasurementConfigurationValueCodec {
		sealed := s24.IntersystemMeasurementConfigurationValueCodec{}
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldPath(&sealed) = "IntersystemMeasurementConfiguration"
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.IntersystemMeasurementConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s24.IntersystemMeasurementConfiguration
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(311), raw)
			if err != nil {
				var empty s24.IntersystemMeasurementConfiguration
				return empty, err
			}
			value, ok := decoded.AsIntersystemMeasurementConfiguration()
			if !ok {
				var empty s24.IntersystemMeasurementConfiguration
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-IntersystemMeasurementConfiguration: no selected value")
			}
			return *value, nil
		}
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldEncode(&sealed) = func(value s24.IntersystemMeasurementConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(311), rowIntersystemMeasurementConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldCapture(&sealed) = func(v s24.IntersystemMeasurementConfiguration, options aper.DecodeState) (s24.IntersystemMeasurementConfiguration, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s24.BridgeCaptureS1APIntersystemMeasurementConfiguration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldCompare(&sealed) = func(v s24.IntersystemMeasurementConfiguration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APIntersystemMeasurementConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeIntersystemMeasurementConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntersystemMeasurementConfiguration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s24.IntersystemMeasurementConfiguration) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(311), rowIntersystemMeasurementConfiguration: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s24.IntersystemMeasurementConfiguration, bool) {
			return value.AsIntersystemMeasurementConfiguration()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoSourceNodeID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(312), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceNodeID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-SourceNodeID"}}}
}

// SourceNodeID returns the typed binding for the SourceNodeID row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) SourceNodeID() SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding{info: t.infoSourceNodeID(), codec: func() s30.SourceNodeIDValueCodec {
		sealed := s30.SourceNodeIDValueCodec{}
		*s30.BridgeSourceNodeIDValueCodecFieldPath(&sealed) = "SourceNodeID"
		*s30.BridgeSourceNodeIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.SourceNodeID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.SourceNodeID
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(312), raw)
			if err != nil {
				var empty s30.SourceNodeID
				return empty, err
			}
			value, ok := decoded.AsSourceNodeID()
			if !ok {
				var empty s30.SourceNodeID
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-SourceNodeID: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeSourceNodeIDValueCodecFieldEncode(&sealed) = func(value s30.SourceNodeID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(312), rowSourceNodeID: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeSourceNodeIDValueCodecFieldCapture(&sealed) = func(v s30.SourceNodeID, options aper.DecodeState) (s30.SourceNodeID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APSourceNodeID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s30.BridgeSourceNodeIDValueCodecFieldCompare(&sealed) = func(v s30.SourceNodeID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APSourceNodeID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s30.BridgeSourceNodeIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNodeID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.SourceNodeID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(312), rowSourceNodeID: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s30.SourceNodeID, bool) {
			return value.AsSourceNodeID()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoEmergencyIndicator() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(326), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EmergencyIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-EmergencyIndicator"}}}
}

// EmergencyIndicator returns the typed binding for the EmergencyIndicator row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) EmergencyIndicator() SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsEmergencyIndicatorExtBinding{info: t.infoEmergencyIndicator(), codec: func() s00.EmergencyIndicatorValueCodec {
		sealed := s00.EmergencyIndicatorValueCodec{}
		*s00.BridgeEmergencyIndicatorValueCodecFieldPath(&sealed) = "EmergencyIndicator"
		*s00.BridgeEmergencyIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EmergencyIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EmergencyIndicator
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(326), raw)
			if err != nil {
				var empty s00.EmergencyIndicator
				return empty, err
			}
			value, ok := decoded.AsEmergencyIndicator()
			if !ok {
				var empty s00.EmergencyIndicator
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-EmergencyIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEmergencyIndicatorValueCodecFieldEncode(&sealed) = func(value s00.EmergencyIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(326), rowEmergencyIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEmergencyIndicatorValueCodecFieldCapture(&sealed) = func(v s00.EmergencyIndicator, options aper.DecodeState) (s00.EmergencyIndicator, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEmergencyIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s00.BridgeEmergencyIndicatorValueCodecFieldCompare(&sealed) = func(v s00.EmergencyIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEmergencyIndicator(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEmergencyIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EmergencyIndicator) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(326), rowEmergencyIndicator: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.EmergencyIndicator, bool) {
			return value.AsEmergencyIndicator()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoUEContextReferenceatSourceeNB() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(337), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-UEContextReferenceatSourceeNB"}}}
}

// UEContextReferenceatSourceeNB returns the typed binding for the UEContextReferenceatSourceeNB row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) UEContextReferenceatSourceeNB() SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsENBUES1APIDExtBinding{info: t.infoUEContextReferenceatSourceeNB(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(337), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			value, ok := decoded.AsUEContextReferenceatSourceeNB()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-UEContextReferenceatSourceeNB: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(337), rowUEContextReferenceatSourceeNB: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.ENBUES1APID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(337), rowUEContextReferenceatSourceeNB: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.ENBUES1APID, bool) {
			return value.AsUEContextReferenceatSourceeNB()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoSourceSNID() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(343), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-RAN-NODE-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-SourceSNID"}}}
}

// SourceSNID returns the typed binding for the SourceSNID row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) SourceSNID() SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding{info: t.infoSourceSNID(), codec: func() s19.GlobalRANNODEIDValueCodec {
		sealed := s19.GlobalRANNODEIDValueCodec{}
		*s19.BridgeGlobalRANNODEIDValueCodecFieldPath(&sealed) = "GlobalRANNODEID"
		*s19.BridgeGlobalRANNODEIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.GlobalRANNODEID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.GlobalRANNODEID
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(343), raw)
			if err != nil {
				var empty s19.GlobalRANNODEID
				return empty, err
			}
			value, ok := decoded.AsSourceSNID()
			if !ok {
				var empty s19.GlobalRANNODEID
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-SourceSNID: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeGlobalRANNODEIDValueCodecFieldEncode(&sealed) = func(value s19.GlobalRANNODEID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(343), rowSourceSNID: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeGlobalRANNODEIDValueCodecFieldCapture(&sealed) = func(v s19.GlobalRANNODEID, options aper.DecodeState) (s19.GlobalRANNODEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APGlobalRANNODEID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeGlobalRANNODEIDValueCodecFieldCompare(&sealed) = func(v s19.GlobalRANNODEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APGlobalRANNODEID(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s19.BridgeGlobalRANNODEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GlobalRANNODEID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.GlobalRANNODEID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(343), rowSourceSNID: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s19.GlobalRANNODEID, bool) {
			return value.AsSourceSNID()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoDirectForwardingPathAvailability() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(79), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Direct-Forwarding-Path-Availability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-Direct-Forwarding-Path-Availability"}}}
}

// DirectForwardingPathAvailability returns the typed binding for the DirectForwardingPathAvailability row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) DirectForwardingPathAvailability() SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsDirectForwardingPathAvailabilityExtBinding{info: t.infoDirectForwardingPathAvailability(), codec: func() s00.DirectForwardingPathAvailabilityValueCodec {
		sealed := s00.DirectForwardingPathAvailabilityValueCodec{}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldPath(&sealed) = "DirectForwardingPathAvailability"
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DirectForwardingPathAvailability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(79), raw)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, err
			}
			value, ok := decoded.AsDirectForwardingPathAvailability()
			if !ok {
				var empty s00.DirectForwardingPathAvailability
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-Direct-Forwarding-Path-Availability: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDirectForwardingPathAvailabilityValueCodecFieldEncode(&sealed) = func(value s00.DirectForwardingPathAvailability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.DirectForwardingPathAvailability) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(79), rowDirectForwardingPathAvailability: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.DirectForwardingPathAvailability, bool) {
			return value.AsDirectForwardingPathAvailability()
		}}
}
func (SourceeNBToTargeteNBTransparentContainerExtIETable) infoTimeBasedHandoverInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SourceeNBToTargeteNBTransparentContainerExtIEs().ID(), ID: s00.ProtocolExtensionID(350), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeBasedHandoverInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs", Row: "id-TimeBasedHandoverInformation"}}}
}

// TimeBasedHandoverInformation returns the typed binding for the TimeBasedHandoverInformation row of SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) TimeBasedHandoverInformation() SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding {
	return SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding{info: t.infoTimeBasedHandoverInformation(), codec: TimeBasedHandoverInformationValueCodec{path: "TimeBasedHandoverInformation",
		decode: func(data []byte, options aper.DecodeState) (TimeBasedHandoverInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TimeBasedHandoverInformation
				return empty, err
			}
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(350), raw)
			if err != nil {
				var empty TimeBasedHandoverInformation
				return empty, err
			}
			value, ok := decoded.AsTimeBasedHandoverInformation()
			if !ok {
				var empty TimeBasedHandoverInformation
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-TimeBasedHandoverInformation: no selected value")
			}
			return *value, nil
		},
		encode: func(value TimeBasedHandoverInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(350), rowTimeBasedHandoverInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TimeBasedHandoverInformation, options aper.DecodeState) (TimeBasedHandoverInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APTimeBasedHandoverInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v TimeBasedHandoverInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APTimeBasedHandoverInformation(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeBasedHandoverInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TimeBasedHandoverInformation) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
		return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(350), rowTimeBasedHandoverInformation: &value}
	}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*TimeBasedHandoverInformation, bool) {
		return value.AsTimeBasedHandoverInformation()
	}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SourceeNBToTargeteNBTransparentContainerExtIETable.
func (t SourceeNBToTargeteNBTransparentContainerExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(175):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-MobilityInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(194):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-uE-HistoryInformationFromTheUE requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(296):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-IMSvoiceEPSfallbackfrom5G requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(300):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ContextatSource requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(311):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-IntersystemMeasurementConfiguration requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(312):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceNodeID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(326):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-EmergencyIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(337):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-UEContextReferenceatSourceeNB requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(343):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-SourceSNID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(79):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Direct-Forwarding-Path-Availability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(350):
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-TimeBasedHandoverInformation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s00.HandoverType
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(4), raw)
			if err != nil {
				var empty TargetID
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(79), raw)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(125), raw)
			if err != nil {
				var empty s00.SRVCCHOIndication
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(104), raw)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(138), raw)
			if err != nil {
				var empty s00.SourceToTargetTransparentContainer
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(132), raw)
			if err != nil {
				var empty s00.MSClassmark2
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(133), raw)
			if err != nil {
				var empty s00.MSClassmark3
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(127), raw)
			if err != nil {
				var empty s00.CSGId
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(145), raw)
			if err != nil {
				var empty s00.CellAccessMode
				return empty, err
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
			var zero HandoverRequiredIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(150), raw)
			if err != nil {
				var empty s00.PSServiceNotAvailable
				return empty, err
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

// AdditionalRRMPriorityIndexCodec binds the complete APER value type.
func AdditionalRRMPriorityIndexCodec() s00.AdditionalRRMPriorityIndexValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().AdditionalRRMPriorityIndex().Codec()
}

// ContextatSourceCodec binds the complete APER value type.
func ContextatSourceCodec() s19.ContextatSourceValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().ContextatSource().Codec()
}

// DirectForwardingPathAvailabilityCodec binds the complete APER value type.
func DirectForwardingPathAvailabilityCodec() s00.DirectForwardingPathAvailabilityValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Codec()
}

// ENBUES1APIDCodec binds the complete APER value type.
func ENBUES1APIDCodec() s00.ENBUES1APIDValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().UEContextReferenceatSourceeNB().Codec()
}

// EmergencyIndicatorCodec binds the complete APER value type.
func EmergencyIndicatorCodec() s00.EmergencyIndicatorValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().EmergencyIndicator().Codec()
}

// GlobalRANNODEIDCodec binds the complete APER value type.
func GlobalRANNODEIDCodec() s19.GlobalRANNODEIDValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().SourceSNID().Codec()
}

// IMSvoiceEPSfallbackfrom5GCodec binds the complete APER value type.
func IMSvoiceEPSfallbackfrom5GCodec() s01.IMSvoiceEPSfallbackfrom5GValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().IMSvoiceEPSfallbackfrom5G().Codec()
}

// IntersystemMeasurementConfigurationCodec binds the complete APER value type.
func IntersystemMeasurementConfigurationCodec() s24.IntersystemMeasurementConfigurationValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().IntersystemMeasurementConfiguration().Codec()
}

// MSClassmark2Codec binds the complete APER value type.
func MSClassmark2Codec() s01.MSClassmark2ValueCodec {
	return HandoverRequiredIEs().MSClassmark2().Codec()
}

// MSClassmark3Codec binds the complete APER value type.
func MSClassmark3Codec() s01.MSClassmark3ValueCodec {
	return HandoverRequiredIEs().MSClassmark3().Codec()
}

// MutingPatternInformationCodec binds the complete APER value type.
func MutingPatternInformationCodec() s19.MutingPatternInformationValueCodec {
	return SONInformationReplyExtIEs().MutingPatternInformation().Codec()
}

// PSServiceNotAvailableCodec binds the complete APER value type.
func PSServiceNotAvailableCodec() s01.PSServiceNotAvailableValueCodec {
	return HandoverRequiredIEs().PSServiceNotAvailable().Codec()
}

// RIMTransferCodec binds the complete source value type.
func RIMTransferCodec() RIMTransferValueCodec {
	return RIMTransferValueCodec{path: "RIMTransfer", decode: func(data []byte, options aper.DecodeState) (s33.RIMTransfer, error) {
		var value s33.RIMTransfer
		if err := s33.BridgeRIMTransferMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s33.RIMTransfer{}, err
		}
		*s33.BridgeRIMTransferFieldReceived(&value) = true
		*s33.BridgeRIMTransferFieldReceivedAbsolute(&value) = true
		*s33.BridgeRIMTransferFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s33.RIMTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s33.BridgeRIMTransferMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s33.RIMTransfer, options aper.DecodeState) (s33.RIMTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s33.BridgeCaptureS1APRIMTransfer(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s33.RIMTransfer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s33.BridgeCompareS1APRIMTransfer(&v, &s)
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

// S1APIEsMobilityInformationCodec binds the complete APER value type.
func S1APIEsMobilityInformationCodec() s01.S1APIEsMobilityInformationValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().MobilityInformation().Codec()
}

// SRVCCHOIndicationCodec binds the complete APER value type.
func SRVCCHOIndicationCodec() s01.SRVCCHOIndicationValueCodec {
	return HandoverRequiredIEs().SRVCCHOIndication().Codec()
}

// SourceNodeIDCodec binds the complete APER value type.
func SourceNodeIDCodec() s30.SourceNodeIDValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().SourceNodeID().Codec()
}

// TargetIDCodec binds the complete APER value type.
func TargetIDCodec() TargetIDValueCodec { return HandoverRequiredIEs().TargetID().Codec() }

// TargetRNCIDCodec binds the complete source value type.
func TargetRNCIDCodec() TargetRNCIDValueCodec {
	return TargetRNCIDValueCodec{path: "TargetRNCID", decode: func(data []byte, options aper.DecodeState) (s33.TargetRNCID, error) {
		var value s33.TargetRNCID
		if err := s33.BridgeTargetRNCIDMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s33.TargetRNCID{}, err
		}
		*s33.BridgeTargetRNCIDFieldReceived(&value) = true
		*s33.BridgeTargetRNCIDFieldReceivedAbsolute(&value) = true
		*s33.BridgeTargetRNCIDFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s33.TargetRNCID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s33.BridgeTargetRNCIDMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s33.TargetRNCID, options aper.DecodeState) (s33.TargetRNCID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s33.BridgeCaptureS1APTargetRNCID(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v s33.TargetRNCID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s33.BridgeCompareS1APTargetRNCID(&v, &s)
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

// TimeBasedHandoverInformationCodec binds the complete APER value type.
func TimeBasedHandoverInformationCodec() TimeBasedHandoverInformationValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().TimeBasedHandoverInformation().Codec()
}

// TimeSynchronisationInfoCodec binds the complete APER value type.
func TimeSynchronisationInfoCodec() TimeSynchronisationInfoValueCodec {
	return SONInformationReplyExtIEs().TimeSynchronisationInfo().Codec()
}

// UEHistoryInformationFromTheUECodec binds the complete APER value type.
func UEHistoryInformationFromTheUECodec() s02.UEHistoryInformationFromTheUEValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().UEHistoryInformationFromTheUE().Codec()
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
func BridgeHandoverRequiredAPERValueFieldContext(v *HandoverRequiredAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequiredAPERValueFieldReceived(v *HandoverRequiredAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequiredAPERValueFieldReplay(v *HandoverRequiredAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequiredAPERValueFieldWithoutReplay(v *HandoverRequiredAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeHandoverRequiredFieldExtCount(v *HandoverRequired) *int64   { return &v.extCount }
func BridgeHandoverRequiredFieldExtData(v *HandoverRequired) *[][]byte { return &v.extData }
func BridgeHandoverRequiredFieldExtOrigin(v *HandoverRequired) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverRequiredFieldExtPresent(v *HandoverRequired) *[]bool       { return &v.extPresent }
func BridgeHandoverRequiredFieldExtWire(v *HandoverRequired) *[]aper.WireSpan { return &v.extWire }
func BridgeHandoverRequiredFieldPerExtPadding(v *HandoverRequired) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverRequiredFieldPerPadding(v *HandoverRequired) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverRequiredFieldProtocolIEsIndef(v *HandoverRequired) *bool {
	return &v.protocolIEsIndef
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
func BridgeHandoverRequiredFieldReplay(v *HandoverRequired) *aper.Snapshot { return &v.replay }
func BridgeHandoverRequiredFieldStream(v *HandoverRequired) *aper.WireSpan { return &v.stream }
func BridgeHandoverRequiredFieldWithoutReplay(v *HandoverRequired) *bool   { return &v.withoutReplay }
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
func BridgeHandoverRequiredMethodMarshalAPERBudget(v *HandoverRequired, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverRequiredMethodMarshalAPERBudgetValue(v *HandoverRequired, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverRequiredMethodMarshalAPERChanged(v *HandoverRequired, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverRequiredMethodMarshalAPERChangedValue(v *HandoverRequired, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverRequiredMethodMarshalAPERLegacy(v *HandoverRequired) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverRequiredMethodMarshalAPERNewValue(v *HandoverRequired, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverRequiredMethodMarshalAPERPlanned(v *HandoverRequired, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverRequiredMethodMarshalAPERTo(v *HandoverRequired, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequiredMethodUnmarshalAPERFrom(v *HandoverRequired, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequiredMethodUnmarshalAPERLegacy(v *HandoverRequired, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverRequiredMethodUnmarshalAPERWithOptions(v *HandoverRequired, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
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
func BridgeHandoverRequiredValueCodecMethodEncodeBudgetValue(v HandoverRequiredValueCodec, a0 HandoverRequired, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequiredValueCodecMethodEncodeChanged(v HandoverRequiredValueCodec, a0 HandoverRequired, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeRIMTransferValueCodecFieldCapture(v *RIMTransferValueCodec) *func(s33.RIMTransfer, aper.DecodeState) (s33.RIMTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMTransferValueCodecFieldCompare(v *RIMTransferValueCodec) *func(s33.RIMTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMTransferValueCodecFieldContext(v *RIMTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMTransferValueCodecFieldDecode(v *RIMTransferValueCodec) *func([]byte, aper.DecodeState) (s33.RIMTransfer, error) {
	return &v.decode
}
func BridgeRIMTransferValueCodecFieldEncode(v *RIMTransferValueCodec) *func(s33.RIMTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMTransferValueCodecFieldPath(v *RIMTransferValueCodec) *aper.Path { return &v.path }
func BridgeRIMTransferValueCodecMethodEncodeBudgetValue(v RIMTransferValueCodec, a0 s33.RIMTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRIMTransferValueCodecMethodEncodeChanged(v RIMTransferValueCodec, a0 s33.RIMTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationReplyExtIETableMethodInfoMutingPatternInformation(v SONInformationReplyExtIETable) s00.ExtensionInfo {
	return v.infoMutingPatternInformation()
}
func BridgeSONInformationReplyExtIETableMethodInfoTimeSynchronisationInfo(v SONInformationReplyExtIETable) s00.ExtensionInfo {
	return v.infoTimeSynchronisationInfo()
}
func BridgeSONInformationReplyExtIEsExtContainerAPERValueFieldContext(v *SONInformationReplyExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyExtIEsExtContainerAPERValueFieldReceived(v *SONInformationReplyExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationReplyExtIEsExtContainerAPERValueFieldReplay(v *SONInformationReplyExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyExtIEsExtContainerAPERValueFieldWithoutReplay(v *SONInformationReplyExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldCapture(v *SONInformationReplyExtIEsExtContainerValueCodec) *func(SONInformationReplyExtIEsExtContainer, aper.DecodeState) (SONInformationReplyExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldCompare(v *SONInformationReplyExtIEsExtContainerValueCodec) *func(SONInformationReplyExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldContext(v *SONInformationReplyExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldDecode(v *SONInformationReplyExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SONInformationReplyExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldEncode(v *SONInformationReplyExtIEsExtContainerValueCodec) *func(SONInformationReplyExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecFieldPath(v *SONInformationReplyExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v SONInformationReplyExtIEsExtContainerValueCodec, a0 SONInformationReplyExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationReplyExtIEsExtContainerValueCodecMethodEncodeChanged(v SONInformationReplyExtIEsExtContainerValueCodec, a0 SONInformationReplyExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationReplyExtIEsExtFieldAPERValueFieldContext(v *SONInformationReplyExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyExtIEsExtFieldAPERValueFieldReceived(v *SONInformationReplyExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationReplyExtIEsExtFieldAPERValueFieldReplay(v *SONInformationReplyExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyExtIEsExtFieldAPERValueFieldWithoutReplay(v *SONInformationReplyExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReplyExtIEsExtFieldFieldReceived(v *SONInformationReplyExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeSONInformationReplyExtIEsExtFieldFieldReplay(v *SONInformationReplyExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyExtIEsExtFieldFieldStream(v *SONInformationReplyExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeSONInformationReplyExtIEsExtFieldFieldWithoutReplay(v *SONInformationReplyExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReplyExtIEsExtFieldMethodMarshalAPERTo(v *SONInformationReplyExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationReplyExtIEsExtFieldMethodUnmarshalAPERFrom(v *SONInformationReplyExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldCapture(v *SONInformationReplyExtIEsExtFieldValueCodec) *func(SONInformationReplyExtIEsExtField, aper.DecodeState) (SONInformationReplyExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldCompare(v *SONInformationReplyExtIEsExtFieldValueCodec) *func(SONInformationReplyExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldContext(v *SONInformationReplyExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldDecode(v *SONInformationReplyExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SONInformationReplyExtIEsExtField, error) {
	return &v.decode
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldEncode(v *SONInformationReplyExtIEsExtFieldValueCodec) *func(SONInformationReplyExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecFieldPath(v *SONInformationReplyExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v SONInformationReplyExtIEsExtFieldValueCodec, a0 SONInformationReplyExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationReplyExtIEsExtFieldValueCodecMethodEncodeChanged(v SONInformationReplyExtIEsExtFieldValueCodec, a0 SONInformationReplyExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationReplyExtIEsIEFieldFieldReceived(v *SONInformationReplyExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSONInformationReplyExtIEsIEFieldFieldReplay(v *SONInformationReplyExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyExtIEsIEFieldFieldStream(v *SONInformationReplyExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSONInformationReplyExtIEsIEFieldFieldWithoutReplay(v *SONInformationReplyExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReplyExtIEsIEFieldMethodMarshalAPERTo(v *SONInformationReplyExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationReplyExtIEsIEFieldMethodUnmarshalAPERFrom(v *SONInformationReplyExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationReplyExtIEsMutingPatternInformationExtBindingFieldCodec(v *SONInformationReplyExtIEsMutingPatternInformationExtBinding) *s19.MutingPatternInformationValueCodec {
	return &v.codec
}
func BridgeSONInformationReplyExtIEsMutingPatternInformationExtBindingFieldGet(v *SONInformationReplyExtIEsMutingPatternInformationExtBinding) *func(*SONInformationReplyExtIEsValue) (*s19.MutingPatternInformation, bool) {
	return &v.get
}
func BridgeSONInformationReplyExtIEsMutingPatternInformationExtBindingFieldInfo(v *SONInformationReplyExtIEsMutingPatternInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSONInformationReplyExtIEsMutingPatternInformationExtBindingFieldInject(v *SONInformationReplyExtIEsMutingPatternInformationExtBinding) *func(s19.MutingPatternInformation) SONInformationReplyExtIEsValue {
	return &v.inject
}
func BridgeSONInformationReplyExtIEsTimeSynchronisationInfoExtBindingFieldCodec(v *SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) *TimeSynchronisationInfoValueCodec {
	return &v.codec
}
func BridgeSONInformationReplyExtIEsTimeSynchronisationInfoExtBindingFieldGet(v *SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) *func(*SONInformationReplyExtIEsValue) (*TimeSynchronisationInfo, bool) {
	return &v.get
}
func BridgeSONInformationReplyExtIEsTimeSynchronisationInfoExtBindingFieldInfo(v *SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSONInformationReplyExtIEsTimeSynchronisationInfoExtBindingFieldInject(v *SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding) *func(TimeSynchronisationInfo) SONInformationReplyExtIEsValue {
	return &v.inject
}
func BridgeSONInformationReplyExtIEsValueFieldId(v *SONInformationReplyExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSONInformationReplyExtIEsValueFieldIsOpaque(v *SONInformationReplyExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSONInformationReplyExtIEsValueFieldOpaque(v *SONInformationReplyExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSONInformationReplyExtIEsValueFieldReceived(v *SONInformationReplyExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationReplyExtIEsValueFieldReplay(v *SONInformationReplyExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyExtIEsValueFieldRowMutingPatternInformation(v *SONInformationReplyExtIEsValue) **s19.MutingPatternInformation {
	return &v.rowMutingPatternInformation
}
func BridgeSONInformationReplyExtIEsValueFieldRowTimeSynchronisationInfo(v *SONInformationReplyExtIEsValue) **TimeSynchronisationInfo {
	return &v.rowTimeSynchronisationInfo
}
func BridgeSONInformationReplyExtIEsValueMethodCaptureSemantics(v SONInformationReplyExtIEsValue, a0 aper.SemanticCapture) SONInformationReplyExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSONInformationReplyExtIEsValueMethodCompareSemantics(v SONInformationReplyExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSONInformationReplyExtIEsValueMethodDecode(v SONInformationReplyExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SONInformationReplyExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSONInformationReplyExtIEsValueMethodEncode(v SONInformationReplyExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeSONInformationReplyExtIEsValueMethodEncodeFresh(v SONInformationReplyExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSONInformationReplyExtIEsValueMethodMatchesID(v SONInformationReplyExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSONInformationReplyExtIEsValueMethodReason(v SONInformationReplyExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSONInformationReplyExtIEsValueMethodRule(v SONInformationReplyExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoAdditionalRRMPriorityIndex(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoContextatSource(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoContextatSource()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoDirectForwardingPathAvailability(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoDirectForwardingPathAvailability()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoEmergencyIndicator(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoEmergencyIndicator()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoIMSvoiceEPSfallbackfrom5G(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoIMSvoiceEPSfallbackfrom5G()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoIntersystemMeasurementConfiguration(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoIntersystemMeasurementConfiguration()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoMobilityInformation(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoMobilityInformation()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoSourceNodeID(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoSourceNodeID()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoSourceSNID(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoSourceSNID()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoTimeBasedHandoverInformation(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoTimeBasedHandoverInformation()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoUEContextReferenceatSourceeNB(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoUEContextReferenceatSourceeNB()
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIETableMethodInfoUEHistoryInformationFromTheUE(v SourceeNBToTargeteNBTransparentContainerExtIETable) s00.ExtensionInfo {
	return v.infoUEHistoryInformationFromTheUE()
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *s19.ContextatSourceValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s19.ContextatSource, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsContextatSourceExtBinding) *func(s19.ContextatSource) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValueFieldContext(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValueFieldReceived(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValueFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValueFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec, a0 SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodecMethodEncodeChanged(v SourceeNBToTargeteNBTransparentContainerExtIEsExtContainerValueCodec, a0 SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldFieldReceived(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldFieldStream(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) *aper.WireSpan {
	return &v.stream
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldCapture(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldCompare(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldContext(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldDecode(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	return &v.decode
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldEncode(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *func(SourceeNBToTargeteNBTransparentContainerExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecFieldPath(v *SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec, a0 SourceeNBToTargeteNBTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodecMethodEncodeChanged(v SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec, a0 SourceeNBToTargeteNBTransparentContainerExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) *s19.GlobalRANNODEIDValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s19.GlobalRANNODEID, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding) *func(s19.GlobalRANNODEID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldFieldReceived(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldFieldStream(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldFieldWithoutReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldMethodMarshalAPERTo(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIEFieldMethodUnmarshalAPERFrom(v *SourceeNBToTargeteNBTransparentContainerExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) *s01.IMSvoiceEPSfallbackfrom5GValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.IMSvoiceEPSfallbackfrom5G, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding) *func(s00.IMSvoiceEPSfallbackfrom5G) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) *s24.IntersystemMeasurementConfigurationValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s24.IntersystemMeasurementConfiguration, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding) *func(s24.IntersystemMeasurementConfiguration) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) *s01.S1APIEsMobilityInformationValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.S1APIEsMobilityInformation, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding) *func(s00.S1APIEsMobilityInformation) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *s30.SourceNodeIDValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s30.SourceNodeID, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *func(s30.SourceNodeID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) *TimeBasedHandoverInformationValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*TimeBasedHandoverInformation, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding) *func(TimeBasedHandoverInformation) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) *s02.UEHistoryInformationFromTheUEValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s00.UEHistoryInformationFromTheUE, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding) *func(s00.UEHistoryInformationFromTheUE) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
	return &v.inject
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldReceived(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldReplay(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowAdditionalRRMPriorityIndex(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowContextatSource(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s19.ContextatSource {
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowIntersystemMeasurementConfiguration(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s24.IntersystemMeasurementConfiguration {
	return &v.rowIntersystemMeasurementConfiguration
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowMobilityInformation(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s00.S1APIEsMobilityInformation {
	return &v.rowMobilityInformation
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceNodeID(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s30.SourceNodeID {
	return &v.rowSourceNodeID
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceSNID(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s19.GlobalRANNODEID {
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueMethodEncode(v SourceeNBToTargeteNBTransparentContainerExtIEsValue) ([]byte, error) {
	return v.encode()
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
func BridgeTargetRNCIDValueCodecFieldCapture(v *TargetRNCIDValueCodec) *func(s33.TargetRNCID, aper.DecodeState) (s33.TargetRNCID, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetRNCIDValueCodecFieldCompare(v *TargetRNCIDValueCodec) *func(s33.TargetRNCID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetRNCIDValueCodecFieldContext(v *TargetRNCIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCIDValueCodecFieldDecode(v *TargetRNCIDValueCodec) *func([]byte, aper.DecodeState) (s33.TargetRNCID, error) {
	return &v.decode
}
func BridgeTargetRNCIDValueCodecFieldEncode(v *TargetRNCIDValueCodec) *func(s33.TargetRNCID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetRNCIDValueCodecFieldPath(v *TargetRNCIDValueCodec) *aper.Path { return &v.path }
func BridgeTargetRNCIDValueCodecMethodEncodeBudgetValue(v TargetRNCIDValueCodec, a0 s33.TargetRNCID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTargetRNCIDValueCodecMethodEncodeChanged(v TargetRNCIDValueCodec, a0 s33.TargetRNCID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeTimeBasedHandoverInformationAPERValueFieldContext(v *TimeBasedHandoverInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeBasedHandoverInformationAPERValueFieldReceived(v *TimeBasedHandoverInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeBasedHandoverInformationAPERValueFieldReplay(v *TimeBasedHandoverInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeBasedHandoverInformationAPERValueFieldWithoutReplay(v *TimeBasedHandoverInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeBasedHandoverInformationFieldExtCount(v *TimeBasedHandoverInformation) *int64 {
	return &v.extCount
}
func BridgeTimeBasedHandoverInformationFieldExtData(v *TimeBasedHandoverInformation) *[][]byte {
	return &v.extData
}
func BridgeTimeBasedHandoverInformationFieldExtOrigin(v *TimeBasedHandoverInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTimeBasedHandoverInformationFieldExtPresent(v *TimeBasedHandoverInformation) *[]bool {
	return &v.extPresent
}
func BridgeTimeBasedHandoverInformationFieldExtWire(v *TimeBasedHandoverInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeTimeBasedHandoverInformationFieldIEExtensionsIndef(v *TimeBasedHandoverInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTimeBasedHandoverInformationFieldPerExtPadding(v *TimeBasedHandoverInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTimeBasedHandoverInformationFieldPerPadding(v *TimeBasedHandoverInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTimeBasedHandoverInformationFieldReceived(v *TimeBasedHandoverInformation) *bool {
	return &v.received
}
func BridgeTimeBasedHandoverInformationFieldReceivedAbsolute(v *TimeBasedHandoverInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeTimeBasedHandoverInformationFieldReceivedBytes(v *TimeBasedHandoverInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTimeBasedHandoverInformationFieldReceivedLocation(v *TimeBasedHandoverInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeTimeBasedHandoverInformationFieldReplay(v *TimeBasedHandoverInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeBasedHandoverInformationFieldStream(v *TimeBasedHandoverInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeTimeBasedHandoverInformationFieldWithoutReplay(v *TimeBasedHandoverInformation) *bool {
	return &v.withoutReplay
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERBudget(v *TimeBasedHandoverInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERBudgetValue(v *TimeBasedHandoverInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERChanged(v *TimeBasedHandoverInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERChangedValue(v *TimeBasedHandoverInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERLegacy(v *TimeBasedHandoverInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERNewValue(v *TimeBasedHandoverInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERPlanned(v *TimeBasedHandoverInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTimeBasedHandoverInformationMethodMarshalAPERTo(v *TimeBasedHandoverInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTimeBasedHandoverInformationMethodUnmarshalAPERFrom(v *TimeBasedHandoverInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTimeBasedHandoverInformationMethodUnmarshalAPERLegacy(v *TimeBasedHandoverInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTimeBasedHandoverInformationMethodUnmarshalAPERWithOptions(v *TimeBasedHandoverInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTimeBasedHandoverInformationValueCodecFieldCapture(v *TimeBasedHandoverInformationValueCodec) *func(TimeBasedHandoverInformation, aper.DecodeState) (TimeBasedHandoverInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeBasedHandoverInformationValueCodecFieldCompare(v *TimeBasedHandoverInformationValueCodec) *func(TimeBasedHandoverInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeBasedHandoverInformationValueCodecFieldContext(v *TimeBasedHandoverInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeBasedHandoverInformationValueCodecFieldDecode(v *TimeBasedHandoverInformationValueCodec) *func([]byte, aper.DecodeState) (TimeBasedHandoverInformation, error) {
	return &v.decode
}
func BridgeTimeBasedHandoverInformationValueCodecFieldEncode(v *TimeBasedHandoverInformationValueCodec) *func(TimeBasedHandoverInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeBasedHandoverInformationValueCodecFieldPath(v *TimeBasedHandoverInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeBasedHandoverInformationValueCodecMethodEncodeBudgetValue(v TimeBasedHandoverInformationValueCodec, a0 TimeBasedHandoverInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeBasedHandoverInformationValueCodecMethodEncodeChanged(v TimeBasedHandoverInformationValueCodec, a0 TimeBasedHandoverInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeSynchronisationInfoAPERValueFieldContext(v *TimeSynchronisationInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeSynchronisationInfoAPERValueFieldReceived(v *TimeSynchronisationInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeSynchronisationInfoAPERValueFieldReplay(v *TimeSynchronisationInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeSynchronisationInfoAPERValueFieldWithoutReplay(v *TimeSynchronisationInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeSynchronisationInfoFieldExtCount(v *TimeSynchronisationInfo) *int64 {
	return &v.extCount
}
func BridgeTimeSynchronisationInfoFieldExtData(v *TimeSynchronisationInfo) *[][]byte {
	return &v.extData
}
func BridgeTimeSynchronisationInfoFieldExtOrigin(v *TimeSynchronisationInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTimeSynchronisationInfoFieldExtPresent(v *TimeSynchronisationInfo) *[]bool {
	return &v.extPresent
}
func BridgeTimeSynchronisationInfoFieldExtWire(v *TimeSynchronisationInfo) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeTimeSynchronisationInfoFieldIEExtensionsIndef(v *TimeSynchronisationInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTimeSynchronisationInfoFieldPerExtPadding(v *TimeSynchronisationInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTimeSynchronisationInfoFieldPerPadding(v *TimeSynchronisationInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTimeSynchronisationInfoFieldReceived(v *TimeSynchronisationInfo) *bool { return &v.received }
func BridgeTimeSynchronisationInfoFieldReceivedAbsolute(v *TimeSynchronisationInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeTimeSynchronisationInfoFieldReceivedBytes(v *TimeSynchronisationInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTimeSynchronisationInfoFieldReceivedLocation(v *TimeSynchronisationInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeTimeSynchronisationInfoFieldReplay(v *TimeSynchronisationInfo) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeSynchronisationInfoFieldStream(v *TimeSynchronisationInfo) *aper.WireSpan {
	return &v.stream
}
func BridgeTimeSynchronisationInfoFieldWithoutReplay(v *TimeSynchronisationInfo) *bool {
	return &v.withoutReplay
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERBudget(v *TimeSynchronisationInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERBudgetValue(v *TimeSynchronisationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERChanged(v *TimeSynchronisationInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERChangedValue(v *TimeSynchronisationInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERLegacy(v *TimeSynchronisationInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERNewValue(v *TimeSynchronisationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERPlanned(v *TimeSynchronisationInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTimeSynchronisationInfoMethodMarshalAPERTo(v *TimeSynchronisationInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTimeSynchronisationInfoMethodUnmarshalAPERFrom(v *TimeSynchronisationInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTimeSynchronisationInfoMethodUnmarshalAPERLegacy(v *TimeSynchronisationInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTimeSynchronisationInfoMethodUnmarshalAPERWithOptions(v *TimeSynchronisationInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTimeSynchronisationInfoValueCodecFieldCapture(v *TimeSynchronisationInfoValueCodec) *func(TimeSynchronisationInfo, aper.DecodeState) (TimeSynchronisationInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeSynchronisationInfoValueCodecFieldCompare(v *TimeSynchronisationInfoValueCodec) *func(TimeSynchronisationInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeSynchronisationInfoValueCodecFieldContext(v *TimeSynchronisationInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeSynchronisationInfoValueCodecFieldDecode(v *TimeSynchronisationInfoValueCodec) *func([]byte, aper.DecodeState) (TimeSynchronisationInfo, error) {
	return &v.decode
}
func BridgeTimeSynchronisationInfoValueCodecFieldEncode(v *TimeSynchronisationInfoValueCodec) *func(TimeSynchronisationInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeSynchronisationInfoValueCodecFieldPath(v *TimeSynchronisationInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeSynchronisationInfoValueCodecMethodEncodeBudgetValue(v TimeSynchronisationInfoValueCodec, a0 TimeSynchronisationInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeSynchronisationInfoValueCodecMethodEncodeChanged(v TimeSynchronisationInfoValueCodec, a0 TimeSynchronisationInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceFailureIndicationAPERValueFieldContext(v *TraceFailureIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationAPERValueFieldReceived(v *TraceFailureIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceFailureIndicationAPERValueFieldReplay(v *TraceFailureIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceFailureIndicationAPERValueFieldWithoutReplay(v *TraceFailureIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceFailureIndicationFieldExtCount(v *TraceFailureIndication) *int64   { return &v.extCount }
func BridgeTraceFailureIndicationFieldExtData(v *TraceFailureIndication) *[][]byte { return &v.extData }
func BridgeTraceFailureIndicationFieldExtOrigin(v *TraceFailureIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTraceFailureIndicationFieldExtPresent(v *TraceFailureIndication) *[]bool {
	return &v.extPresent
}
func BridgeTraceFailureIndicationFieldExtWire(v *TraceFailureIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeTraceFailureIndicationFieldPerExtPadding(v *TraceFailureIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTraceFailureIndicationFieldPerPadding(v *TraceFailureIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTraceFailureIndicationFieldProtocolIEsIndef(v *TraceFailureIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeTraceFailureIndicationFieldReceived(v *TraceFailureIndication) *bool { return &v.received }
func BridgeTraceFailureIndicationFieldReceivedAbsolute(v *TraceFailureIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeTraceFailureIndicationFieldReceivedBytes(v *TraceFailureIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTraceFailureIndicationFieldReceivedLocation(v *TraceFailureIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeTraceFailureIndicationFieldReplay(v *TraceFailureIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceFailureIndicationFieldStream(v *TraceFailureIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeTraceFailureIndicationFieldWithoutReplay(v *TraceFailureIndication) *bool {
	return &v.withoutReplay
}
func BridgeTraceFailureIndicationMethodMarshalAPERBudget(v *TraceFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTraceFailureIndicationMethodMarshalAPERBudgetValue(v *TraceFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTraceFailureIndicationMethodMarshalAPERChanged(v *TraceFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTraceFailureIndicationMethodMarshalAPERChangedValue(v *TraceFailureIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTraceFailureIndicationMethodMarshalAPERLegacy(v *TraceFailureIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTraceFailureIndicationMethodMarshalAPERNewValue(v *TraceFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTraceFailureIndicationMethodMarshalAPERPlanned(v *TraceFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTraceFailureIndicationMethodMarshalAPERTo(v *TraceFailureIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceFailureIndicationMethodUnmarshalAPERFrom(v *TraceFailureIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceFailureIndicationMethodUnmarshalAPERLegacy(v *TraceFailureIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTraceFailureIndicationMethodUnmarshalAPERWithOptions(v *TraceFailureIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTraceFailureIndicationValueCodecFieldCapture(v *TraceFailureIndicationValueCodec) *func(TraceFailureIndication, aper.DecodeState) (TraceFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceFailureIndicationValueCodecFieldCompare(v *TraceFailureIndicationValueCodec) *func(TraceFailureIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceFailureIndicationValueCodecFieldContext(v *TraceFailureIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceFailureIndicationValueCodecFieldDecode(v *TraceFailureIndicationValueCodec) *func([]byte, aper.DecodeState) (TraceFailureIndication, error) {
	return &v.decode
}
func BridgeTraceFailureIndicationValueCodecFieldEncode(v *TraceFailureIndicationValueCodec) *func(TraceFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceFailureIndicationValueCodecFieldPath(v *TraceFailureIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceFailureIndicationValueCodecMethodEncodeBudgetValue(v TraceFailureIndicationValueCodec, a0 TraceFailureIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceFailureIndicationValueCodecMethodEncodeChanged(v TraceFailureIndicationValueCodec, a0 TraceFailureIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTunnelInformationFieldExtCount(v *TunnelInformation) *int64   { return &v.extCount }
func BridgeTunnelInformationFieldExtData(v *TunnelInformation) *[][]byte { return &v.extData }
func BridgeTunnelInformationFieldExtOrigin(v *TunnelInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeTunnelInformationFieldExtPresent(v *TunnelInformation) *[]bool       { return &v.extPresent }
func BridgeTunnelInformationFieldExtWire(v *TunnelInformation) *[]aper.WireSpan { return &v.extWire }
func BridgeTunnelInformationFieldIEExtensionsIndef(v *TunnelInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeTunnelInformationFieldPerExtPadding(v *TunnelInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTunnelInformationFieldPerPadding(v *TunnelInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeTunnelInformationFieldReceived(v *TunnelInformation) *bool { return &v.received }
func BridgeTunnelInformationFieldReceivedAbsolute(v *TunnelInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeTunnelInformationFieldReceivedBytes(v *TunnelInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTunnelInformationFieldReceivedLocation(v *TunnelInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeTunnelInformationFieldReplay(v *TunnelInformation) *aper.Snapshot { return &v.replay }
func BridgeTunnelInformationFieldStream(v *TunnelInformation) *aper.WireSpan { return &v.stream }
func BridgeTunnelInformationFieldWithoutReplay(v *TunnelInformation) *bool   { return &v.withoutReplay }
func BridgeTunnelInformationMethodMarshalAPERBudget(v *TunnelInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTunnelInformationMethodMarshalAPERBudgetValue(v *TunnelInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTunnelInformationMethodMarshalAPERChanged(v *TunnelInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTunnelInformationMethodMarshalAPERChangedValue(v *TunnelInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTunnelInformationMethodMarshalAPERLegacy(v *TunnelInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTunnelInformationMethodMarshalAPERNewValue(v *TunnelInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTunnelInformationMethodMarshalAPERPlanned(v *TunnelInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTunnelInformationMethodMarshalAPERTo(v *TunnelInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTunnelInformationMethodUnmarshalAPERFrom(v *TunnelInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTunnelInformationMethodUnmarshalAPERLegacy(v *TunnelInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTunnelInformationMethodUnmarshalAPERWithOptions(v *TunnelInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
