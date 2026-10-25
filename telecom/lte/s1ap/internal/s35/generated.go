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
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// HandoverNotifyIEContainer is ProtocolIE-Container {{HandoverNotifyIEs}} of TS 36.413: a list of HandoverNotifyIEField values.
type HandoverNotifyIEContainer []HandoverNotifyIEField

// HandoverNotifyIEField is ProtocolIE-Field {{HandoverNotifyIEs}} of TS 36.413: an information element field.
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

// InitialUEMessageIEContainer is ProtocolIE-Container {{InitialUEMessage-IEs}} of TS 36.413: a list of InitialUEMessageIEField values.
type InitialUEMessageIEContainer []InitialUEMessageIEField

// InitialUEMessageIEField is ProtocolIE-Field {{InitialUEMessage-IEs}} of TS 36.413: an information element field.
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
func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainer(v *s34.HandoverRequiredIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(v *s34.HandoverRequiredIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainer(v *s21.TraceFailureIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainer(v *s21.TraceFailureIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.TunnelInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.TunnelInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// SONInformationReplyExtIEsExtContainer is ProtocolExtensionContainer {{SONInformationReply-ExtIEs}} of TS 36.413: a list of SONInformationReplyExtIEsExtField values.
type SONInformationReplyExtIEsExtContainer []SONInformationReplyExtIEsExtField

// SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer is ProtocolExtensionContainer {{SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs}} of TS 36.413: a list of SourceeNBToTargeteNBTransparentContainerExtIEsExtField values.
type SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer []SourceeNBToTargeteNBTransparentContainerExtIEsExtField

// SONInformationReplyExtIEsExtField is ProtocolExtensionField {{SONInformationReply-ExtIEs}} of TS 36.413: an extension field.
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

// SONInformationReplyExtIEsTimeSynchronisationInfoExtBinding binds TimeSynchronisationInfo to the SONInformationReply-ExtIEs object set of TS 36.413.
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

// SONInformationReplyExtIEsMutingPatternInformationExtBinding binds MutingPatternInformation to the SONInformationReply-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsS1APIEsMobilityInformationExtBinding binds S1APIEsMobilityInformation to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsUEHistoryInformationFromTheUEExtBinding binds UEHistoryInformationFromTheUE to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsIMSvoiceEPSfallbackfrom5GExtBinding binds IMSvoiceEPSfallbackfrom5G to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsIntersystemMeasurementConfigurationExtBinding binds IntersystemMeasurementConfiguration to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding binds SourceNodeID to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
type SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding struct {
	info   s00.ExtensionInfo
	codec  s31.SourceNodeIDValueCodec
	inject func(s31.SourceNodeID,

	) SourceeNBToTargeteNBTransparentContainerExtIEsValue

	get func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue,

	) (*s31.SourceNodeID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Codec() s31.SourceNodeIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) New(value s31.SourceNodeID,

) (SourceeNBToTargeteNBTransparentContainerExtIEsExtField, error) {
	if b.inject == nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSourceNodeIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SourceeNBToTargeteNBTransparentContainerExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) Get(field *SourceeNBToTargeteNBTransparentContainerExtIEsExtField) (*s31.SourceNodeID,

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

// SourceeNBToTargeteNBTransparentContainerExtIEsGlobalRANNODEIDExtBinding binds GlobalRANNODEID to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsTimeBasedHandoverInformationExtBinding binds TimeBasedHandoverInformation to the SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs object set of TS 36.413.
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

// TunnelInformationValueCodec is the concrete ValueCodec[TunnelInformation].
type TunnelInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TunnelInformation,

		error)
	encode func(TunnelInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TunnelInformation, aper.DecodeState,

	) (TunnelInformation, aper.Snapshot,

	)
	compare func(TunnelInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TunnelInformationValueCodec) New(value TunnelInformation,

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
func (c TunnelInformationValueCodec) encodeBudgetValue(value TunnelInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TunnelInformationValueCodec) encodeChanged(value TunnelInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverNotifyMMEUES1APIDIEBinding binds MMEUES1APID to the HandoverNotifyIEs object set of TS 36.413.
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

// HandoverNotifyENBUES1APIDIEBinding binds ENBUES1APID to the HandoverNotifyIEs object set of TS 36.413.
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

// HandoverNotifyEUTRANCGIIEBinding binds EUTRANCGI to the HandoverNotifyIEs object set of TS 36.413.
type HandoverNotifyEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyEUTRANCGIIEBinding) Codec() s18.EUTRANCGIValueCodec { return b.codec }

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
	if _, err := (*s18.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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

// HandoverNotifyTAIIEBinding binds TAI to the HandoverNotifyIEs object set of TS 36.413.
type HandoverNotifyTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s32.TAI,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*s32.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverNotifyTAIIEBinding) New(value s32.TAI,

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
func (b HandoverNotifyTAIIEBinding) Get(field *HandoverNotifyIEField) (*s32.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyTunnelInformationIEBinding binds TunnelInformation to the HandoverNotifyIEs object set of TS 36.413.
type HandoverNotifyTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  TunnelInformationValueCodec
	inject func(TunnelInformation,

	) HandoverNotifyIEValue

	get func(*HandoverNotifyIEValue,

	) (*TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverNotifyTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverNotifyTunnelInformationIEBinding) Codec() TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b HandoverNotifyTunnelInformationIEBinding) New(value TunnelInformation,

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
func (b HandoverNotifyTunnelInformationIEBinding) Get(field *HandoverNotifyIEField) (*TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverNotifyLHNIDIEBinding binds LHNID to the HandoverNotifyIEs object set of TS 36.413.
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

// HandoverNotifyPSCellInformationIEBinding binds PSCellInformation to the HandoverNotifyIEs object set of TS 36.413.
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

// HandoverNotifyNotifySourceeNBIEBinding binds NotifySourceeNB to the HandoverNotifyIEs object set of TS 36.413.
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

// HandoverNotifyLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the HandoverNotifyIEs object set of TS 36.413.
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

// InitialUEMessageENBUES1APIDIEBinding binds ENBUES1APID to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageNASPDUIEBinding binds NASPDU to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageTAIIEBinding binds TAI to the InitialUEMessage-IEs object set of TS 36.413.
type InitialUEMessageTAIIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIValueCodec
	inject func(s32.TAI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s32.TAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageTAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageTAIIEBinding) Codec() s32.TAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageTAIIEBinding) New(value s32.TAI,

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
func (b InitialUEMessageTAIIEBinding) Get(field *InitialUEMessageIEField) (*s32.TAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageEUTRANCGIIEBinding binds EUTRANCGI to the InitialUEMessage-IEs object set of TS 36.413.
type InitialUEMessageEUTRANCGIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.EUTRANCGIValueCodec
	inject func(s17.EUTRANCGI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s17.EUTRANCGI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageEUTRANCGIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageEUTRANCGIIEBinding) Codec() s18.EUTRANCGIValueCodec { return b.codec }

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
	if _, err := (*s18.BridgeEUTRANCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
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

// InitialUEMessageRRCEstablishmentCauseIEBinding binds RRCEstablishmentCause to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageSTMSIIEBinding binds STMSI to the InitialUEMessage-IEs object set of TS 36.413.
type InitialUEMessageSTMSIIEBinding struct {
	info   s00.FieldInfo
	codec  s28.STMSIValueCodec
	inject func(s28.STMSI,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*s28.STMSI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageSTMSIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageSTMSIIEBinding) Codec() s28.STMSIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialUEMessageSTMSIIEBinding) New(value s28.STMSI,

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
func (b InitialUEMessageSTMSIIEBinding) Get(field *InitialUEMessageIEField) (*s28.STMSI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageCSGIdIEBinding binds CSGId to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageGUMMEIIEBinding binds GUMMEI to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageCellAccessModeIEBinding binds CellAccessMode to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageTransportLayerAddressIEBinding binds TransportLayerAddress to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageRelayNodeIndicatorIEBinding binds RelayNodeIndicator to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageGUMMEITypeIEBinding binds GUMMEIType to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageTunnelInformationIEBinding binds TunnelInformation to the InitialUEMessage-IEs object set of TS 36.413.
type InitialUEMessageTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  TunnelInformationValueCodec
	inject func(TunnelInformation,

	) InitialUEMessageIEValue

	get func(*InitialUEMessageIEValue,

	) (*TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialUEMessageTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialUEMessageTunnelInformationIEBinding) Codec() TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialUEMessageTunnelInformationIEBinding) New(value TunnelInformation,

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
func (b InitialUEMessageTunnelInformationIEBinding) Get(field *InitialUEMessageIEField) (*TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialUEMessageLHNIDIEBinding binds LHNID to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageMMEGroupIDIEBinding binds MMEGroupID to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageUEUsageTypeIEBinding binds UEUsageType to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageCEModeBSupportIndicatorIEBinding binds CEModeBSupportIndicator to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageDCNIDIEBinding binds DCNID to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageCoverageLevelIEBinding binds CoverageLevel to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageUEApplicationLayerMeasurementCapabilityIEBinding binds UEApplicationLayerMeasurementCapability to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageEDTSessionIEBinding binds EDTSession to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageIABNodeIndicationIEBinding binds IABNodeIndication to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageLTENTNTAIInformationIEBinding binds LTENTNTAIInformation to the InitialUEMessage-IEs object set of TS 36.413.
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

// InitialUEMessageCoarseUELocationRequestedIEBinding binds CoarseUELocationRequested to the InitialUEMessage-IEs object set of TS 36.413.
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
func BridgeHandoverRequiredIEValueValidateS1APIEContainer(fields s34.HandoverRequiredIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s34.BridgeHandoverRequiredIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s34.BridgeHandoverRequiredIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s34.BridgeHandoverRequiredIEValueMethodRule(field.Value).Assignment
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
func BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(fields s21.TraceFailureIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s21.BridgeTraceFailureIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s21.BridgeTraceFailureIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s21.BridgeTraceFailureIndicationIEValueMethodRule(field.Value).Assignment
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
	if err := aper.ChargeSlice[s12.TimeSynchronisationInfoExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.TimeSynchronisationInfoExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTimeSynchronisationInfoExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// HandoverRequiredIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueERABIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) s34.HandoverRequiredIEValueERABIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s34.BridgeHandoverRequiredIEContainerValueCodecFieldDecode(&codec) == nil {
		return s34.HandoverRequiredIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s34.HandoverRequiredIEValueERABIEContainerListValueCodec {
		sealed := s34.HandoverRequiredIEValueERABIEContainerListValueCodec{}
		*s34.BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.HandoverRequiredIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s34.HandoverRequiredIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s34.HandoverRequiredIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		}
		*s34.BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s34.HandoverRequiredIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s34.BridgeHandoverRequiredIEContainerValueCodecFieldEncode(&codec))(s34.HandoverRequiredIEContainer(value), fresh, budget)
		}
		*s34.BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s34.HandoverRequiredIEValueERABIEContainerList, options aper.DecodeState) (s34.HandoverRequiredIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s34.BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s34.HandoverRequiredIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeHandoverRequiredIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TraceFailureIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{TraceFailureIndicationIEs}} codec of TS 36.413.
func TraceFailureIndicationIEValueERABIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable) s21.TraceFailureIndicationIEValueERABIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.TraceFailureIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.TraceFailureIndicationIEValueERABIEContainerListValueCodec {
		sealed := s21.TraceFailureIndicationIEValueERABIEContainerListValueCodec{}
		*s21.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.TraceFailureIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.TraceFailureIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.TraceFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceFailureIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.TraceFailureIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s21.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.TraceFailureIndicationIEValueERABIEContainerList, options aper.DecodeState) (s21.TraceFailureIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.TraceFailureIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeTraceFailureIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SONInformationReplyExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SONInformationReply-ExtIEs}} codec of TS 36.413.
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
			return field, runtime.WrapDecodePath(err, "SONInformationReplyExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "SONInformationReplyExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "SONInformationReplyExtIEsExtField")
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
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SONInformationReplyExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs}} codec of TS 36.413.
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
			return field, runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainerExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "SourceeNBToTargeteNBTransparentContainerExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainerExtIEsExtField")
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
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SourceeNBToTargeteNBTransparentContainerExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
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

// TimeBasedHandoverInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TimeBasedHandoverInformation-ExtIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeBasedHandoverInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtField")
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TimeBasedHandoverInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTimeBasedHandoverInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// TimeSynchronisationInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{TimeSynchronisationInfo-ExtIEs}} codec of TS 36.413.
func TimeSynchronisationInfoExtIEsValueExtensionFieldTableCodec(table s00.TimeSynchronisationInfoExtIEsValueExtensionTable) s12.TimeSynchronisationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeTimeSynchronisationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s12.TimeSynchronisationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s12.TimeSynchronisationInfoExtIEsExtFieldValueCodec {
		sealed := s12.TimeSynchronisationInfoExtIEsExtFieldValueCodec{}
		*s12.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtField, error) {
			var field s11.TimeSynchronisationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TimeSynchronisationInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeSynchronisationInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TimeSynchronisationInfoExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s11.TimeSynchronisationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtField, options aper.DecodeState) (s11.TimeSynchronisationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TimeSynchronisationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTimeSynchronisationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeTimeSynchronisationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TunnelInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{Tunnel-Information-ExtIEs}} codec of TS 36.413.
func TunnelInformationExtIEsValueExtensionFieldTableCodec(table s00.TunnelInformationExtIEsValueExtensionTable) s12.TunnelInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeTunnelInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.TunnelInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.TunnelInformationExtIEsExtFieldValueCodec {
		sealed := s12.TunnelInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.TunnelInformationExtIEsExtField, error) {
			var field s12.TunnelInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TunnelInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TunnelInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TunnelInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.TunnelInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.TunnelInformationExtIEsExtField, options aper.DecodeState) (s12.TunnelInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeTunnelInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.TunnelInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// SONInformationReplyExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SONInformationReply-ExtIEs}} codec of TS 36.413.
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
			return nil, runtime.WrapDecodePath(err, "SONInformationReplyExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "SONInformationReplyExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "SONInformationReplyExtIEsExtContainer")
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
			f := s.Begin()
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

// SourceeNBToTargeteNBTransparentContainerExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs}} codec of TS 36.413.
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
			return nil, runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "SourceeNBToTargeteNBTransparentContainerExtIEsExtContainer")
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
			f := s.Begin()
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

// TimeBasedHandoverInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TimeBasedHandoverInformation-ExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeBasedHandoverInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TimeBasedHandoverInformationExtIEsExtContainer")
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
			f := s.Begin()
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

// TimeSynchronisationInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TimeSynchronisationInfo-ExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TimeSynchronisationInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TimeSynchronisationInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TimeSynchronisationInfoExtIEsExtContainer")
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
			f := s.Begin()
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

// TunnelInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{Tunnel-Information-ExtIEs}} codec of TS 36.413.
func TunnelInformationExtIEsValueExtensionTableCodec(table s00.TunnelInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s12.TunnelInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeTunnelInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.TunnelInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.TunnelInformationExtIEsExtContainerValueCodec {
		sealed := s12.TunnelInformationExtIEsExtContainerValueCodec{}
		*s12.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.TunnelInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.TunnelInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.TunnelInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TunnelInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TunnelInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TunnelInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.TunnelInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.TunnelInformationExtIEsExtContainer, options aper.DecodeState) (s12.TunnelInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.TunnelInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeTunnelInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverRequiredIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueIEFieldTableCodec(table s00.HandoverRequiredIEValueIETable) s34.HandoverRequiredIEFieldValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return s34.HandoverRequiredIEFieldValueCodec{}
	}
	return func() s34.HandoverRequiredIEFieldValueCodec {
		sealed := s34.HandoverRequiredIEFieldValueCodec{}
		*s34.BridgeHandoverRequiredIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.HandoverRequiredIEField, error) {
			var field s34.HandoverRequiredIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverRequiredIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequiredIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverRequiredIEField")
			}
			return field, nil
		}
		*s34.BridgeHandoverRequiredIEFieldValueCodecFieldEncode(&sealed) = func(field s34.HandoverRequiredIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s34.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s34.BridgeHandoverRequiredIEFieldValueCodecFieldCapture(&sealed) = func(v s34.HandoverRequiredIEField, options aper.DecodeState) (s34.HandoverRequiredIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s34.BridgeHandoverRequiredIEFieldValueCodecFieldCompare(&sealed) = func(v s34.HandoverRequiredIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeHandoverRequiredIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TraceFailureIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{TraceFailureIndicationIEs}} codec of TS 36.413.
func TraceFailureIndicationIEValueIEFieldTableCodec(table s00.TraceFailureIndicationIEValueIETable) s21.TraceFailureIndicationIEFieldValueCodec {
	if !*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&table) {
		return s21.TraceFailureIndicationIEFieldValueCodec{}
	}
	return func() s21.TraceFailureIndicationIEFieldValueCodec {
		sealed := s21.TraceFailureIndicationIEFieldValueCodec{}
		*s21.BridgeTraceFailureIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.TraceFailureIndicationIEField, error) {
			var field s21.TraceFailureIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TraceFailureIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceFailureIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TraceFailureIndicationIEField")
			}
			return field, nil
		}
		*s21.BridgeTraceFailureIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s21.TraceFailureIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeTraceFailureIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s21.TraceFailureIndicationIEField, options aper.DecodeState) (s21.TraceFailureIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeTraceFailureIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s21.TraceFailureIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeTraceFailureIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverRequiredIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueIETableCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) s34.HandoverRequiredIEContainerValueCodec {
	if !*s00.BridgeHandoverRequiredIEValueIETableFieldBound(&table) {
		return s34.HandoverRequiredIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s34.HandoverRequiredIEContainerValueCodec {
		sealed := s34.HandoverRequiredIEContainerValueCodec{}
		*s34.BridgeHandoverRequiredIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.HandoverRequiredIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s34.HandoverRequiredIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s34.HandoverRequiredIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		}
		*s34.BridgeHandoverRequiredIEContainerValueCodecFieldEncode(&sealed) = func(fields s34.HandoverRequiredIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s34.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s34.BridgeHandoverRequiredIEContainerValueCodecFieldCapture(&sealed) = func(v s34.HandoverRequiredIEContainer, options aper.DecodeState) (s34.HandoverRequiredIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s34.BridgeHandoverRequiredIEContainerValueCodecFieldCompare(&sealed) = func(v s34.HandoverRequiredIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeHandoverRequiredIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TraceFailureIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{TraceFailureIndicationIEs}} codec of TS 36.413.
func TraceFailureIndicationIEValueIETableCodec(table s00.TraceFailureIndicationIEValueIETable, bounds aper.ListBounds) s21.TraceFailureIndicationIEContainerValueCodec {
	if !*s00.BridgeTraceFailureIndicationIEValueIETableFieldBound(&table) {
		return s21.TraceFailureIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.TraceFailureIndicationIEContainerValueCodec {
		sealed := s21.TraceFailureIndicationIEContainerValueCodec{}
		*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.TraceFailureIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.TraceFailureIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.TraceFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceFailureIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEContainer")
			}
			return fields, nil
		}
		*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s21.TraceFailureIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s21.TraceFailureIndicationIEContainer, options aper.DecodeState) (s21.TraceFailureIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s21.TraceFailureIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverRequiredIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverRequiredIEs}} codec of TS 36.413.
func HandoverRequiredIEValueProtocolErrorIEContainerListCodec(table s00.HandoverRequiredIEValueIETable) s34.HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s34.BridgeHandoverRequiredIEContainerValueCodecFieldDecode(&codec) == nil {
		return s34.HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s34.HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s34.HandoverRequiredIEValueProtocolErrorIEContainerListValueCodec{}
		*s34.BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.HandoverRequiredIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s34.HandoverRequiredIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s34.HandoverRequiredIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		}
		*s34.BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s34.HandoverRequiredIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s34.BridgeHandoverRequiredIEContainerValueCodecFieldEncode(&codec))(s34.HandoverRequiredIEContainer(value), fresh, budget)
		}
		*s34.BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s34.HandoverRequiredIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s34.HandoverRequiredIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s34.BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s34.HandoverRequiredIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeHandoverRequiredIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TraceFailureIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{TraceFailureIndicationIEs}} codec of TS 36.413.
func TraceFailureIndicationIEValueProtocolErrorIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable) s21.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.TraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.TraceFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceFailureIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s21.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HandoverRequiredIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverRequiredIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverRequiredIEValueProtocolIEContainerListCodec(table s00.HandoverRequiredIEValueIETable, bounds aper.ListBounds) s34.HandoverRequiredIEValueProtocolIEContainerListValueCodec {
	codec := HandoverRequiredIEValueIETableCodec(table, bounds)
	if *s34.BridgeHandoverRequiredIEContainerValueCodecFieldDecode(&codec) == nil {
		return s34.HandoverRequiredIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s34.HandoverRequiredIEValueProtocolIEContainerListValueCodec {
		sealed := s34.HandoverRequiredIEValueProtocolIEContainerListValueCodec{}
		*s34.BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.HandoverRequiredIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s34.HandoverRequiredIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s34.HandoverRequiredIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		}
		*s34.BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s34.HandoverRequiredIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s34.BridgeHandoverRequiredIEContainerValueCodecFieldEncode(&codec))(s34.HandoverRequiredIEContainer(value), fresh, budget)
		}
		*s34.BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s34.HandoverRequiredIEValueProtocolIEContainerList, options aper.DecodeState) (s34.HandoverRequiredIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s34.BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s34.HandoverRequiredIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s34.BridgeHandoverRequiredIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// TraceFailureIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {TraceFailureIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func TraceFailureIndicationIEValueProtocolIEContainerListCodec(table s00.TraceFailureIndicationIEValueIETable, bounds aper.ListBounds) s21.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec {
	codec := TraceFailureIndicationIEValueIETableCodec(table, bounds)
	if *s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s21.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s21.TraceFailureIndicationIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.TraceFailureIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.TraceFailureIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.TraceFailureIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceFailureIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceFailureIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.TraceFailureIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeTraceFailureIndicationIEContainerValueCodecFieldEncode(&codec))(s21.TraceFailureIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.TraceFailureIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s21.TraceFailureIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.TraceFailureIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeTraceFailureIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// handoverRequiredIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverRequiredIEValue].
type HandoverRequiredIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s34.HandoverRequiredIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s34.HandoverRequiredIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(v *s34.HandoverRequiredIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s34.BridgeHandoverRequiredIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s34.BridgeHandoverRequiredIEFieldFieldReplay(v), *s34.BridgeHandoverRequiredIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(v *s34.HandoverRequiredIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s34.BridgeHandoverRequiredIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s34.BridgeHandoverRequiredIEFieldFieldReplay(v), *s34.BridgeHandoverRequiredIEFieldFieldWithoutReplay(v))
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
	captureSemantics(aper.SemanticCapture) s21.TraceFailureIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.TraceFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(v *s21.TraceFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeTraceFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s21.BridgeTraceFailureIndicationIEFieldFieldReplay(v), *s21.BridgeTraceFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(v *s21.TraceFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeTraceFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s21.BridgeTraceFailureIndicationIEFieldFieldReplay(v), *s21.BridgeTraceFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeTunnelInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.TunnelInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeTunnelInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeTunnelInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeTunnelInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeTunnelInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.TunnelInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeTunnelInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeTunnelInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeTunnelInformationExtIEsExtFieldFieldWithoutReplay(v))
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

// TunnelInformationAPERValue is the concrete APERValue[TunnelInformation].
type TunnelInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   TunnelInformation

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

// SONInformationReplyExtIEsIEField uses the ProtocolIE-Field shape for object set SONInformationReply-ExtIEs of TS 36.413.
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

// SONInformationReplyExtIEsIEContainer uses the ProtocolIE-Container shape for object set SONInformationReply-ExtIEs of TS 36.413: a list of SONInformationReplyExtIEsIEField values.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsIEField uses the ProtocolIE-Field shape for object set SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs of TS 36.413.
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

// SourceeNBToTargeteNBTransparentContainerExtIEsIEContainer uses the ProtocolIE-Container shape for object set SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs of TS 36.413: a list of SourceeNBToTargeteNBTransparentContainerExtIEsIEField values.
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeTimeSynchronisationInfoExtIEsValueValidateS1APIEContainer(fields s12.TimeSynchronisationInfoExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// HandoverNotifyIEValueERABIEContainerListValueCodec is the concrete ValueCodec[HandoverNotifyIEValueERABIEContainerList].
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

// HandoverNotifyIEValueERABIEContainerList is E-RAB-IE-ContainerList {{HandoverNotifyIEs}} of TS 36.413: a list of information element fields.
type HandoverNotifyIEValueERABIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverRequiredIEValueCaptureS1APERABIEContainerList(v *s34.HandoverRequiredIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverRequiredIEValueCompareS1APERABIEContainerList(v *s34.HandoverRequiredIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// InitialUEMessageIEValueERABIEContainerListValueCodec is the concrete ValueCodec[InitialUEMessageIEValueERABIEContainerList].
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

// InitialUEMessageIEValueERABIEContainerList is E-RAB-IE-ContainerList {{InitialUEMessage-IEs}} of TS 36.413: a list of information element fields.
type InitialUEMessageIEValueERABIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeTraceFailureIndicationIEValueCaptureS1APERABIEContainerList(v *s21.TraceFailureIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCompareS1APERABIEContainerList(v *s21.TraceFailureIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// SONInformationReplyExtIEsExtFieldValueCodec is the concrete ValueCodec[SONInformationReplyExtIEsExtField].
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

// SourceeNBToTargeteNBTransparentContainerExtIEsExtFieldValueCodec is the concrete ValueCodec[SourceeNBToTargeteNBTransparentContainerExtIEsExtField].
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

// SONInformationReplyExtIEsExtContainerValueCodec is the concrete ValueCodec[SONInformationReplyExtIEsExtContainer].
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

// HandoverNotifyIEFieldValueCodec is the concrete ValueCodec[HandoverNotifyIEField].
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

// InitialUEMessageIEFieldValueCodec is the concrete ValueCodec[InitialUEMessageIEField].
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

// HandoverNotifyIEContainerValueCodec is the concrete ValueCodec[HandoverNotifyIEContainer].
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

// InitialUEMessageIEContainerValueCodec is the concrete ValueCodec[InitialUEMessageIEContainer].
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

// HandoverNotifyIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[HandoverNotifyIEValueProtocolErrorIEContainerList].
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

// HandoverNotifyIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{HandoverNotifyIEs}} of TS 36.413: a list of information element fields.
type HandoverNotifyIEValueProtocolErrorIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverRequiredIEValueCaptureS1APProtocolErrorIEContainerList(v *s34.HandoverRequiredIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverRequiredIEValueCompareS1APProtocolErrorIEContainerList(v *s34.HandoverRequiredIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// InitialUEMessageIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[InitialUEMessageIEValueProtocolErrorIEContainerList].
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

// InitialUEMessageIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{InitialUEMessage-IEs}} of TS 36.413: a list of information element fields.
type InitialUEMessageIEValueProtocolErrorIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s21.TraceFailureIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// HandoverNotifyIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[HandoverNotifyIEValueProtocolIEContainerList].
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

// HandoverNotifyIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {HandoverNotifyIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type HandoverNotifyIEValueProtocolIEContainerList []HandoverNotifyIEValueProtocolIESingleContainer

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIEContainerList(v *s34.HandoverRequiredIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeHandoverRequiredIEValueCompareS1APProtocolIEContainerList(v *s34.HandoverRequiredIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// InitialUEMessageIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[InitialUEMessageIEValueProtocolIEContainerList].
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

// InitialUEMessageIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {InitialUEMessage-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type InitialUEMessageIEValueProtocolIEContainerList []InitialUEMessageIEValueProtocolIESingleContainer

func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEContainerList(v *s21.TraceFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEContainerList(v *s21.TraceFailureIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

// HandoverNotifyIEValueERABIEContainerListAPERValue is the concrete APERValue[HandoverNotifyIEValueERABIEContainerList].
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

// HandoverNotifyIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{HandoverNotifyIEs}} of TS 36.413: a single information element field.
type HandoverNotifyIEValueProtocolIESingleContainer = HandoverNotifyIEField

func BridgeHandoverRequiredIEValueCaptureS1APProtocolIESingleContainer(v *s34.HandoverRequiredIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverRequiredIEValueCompareS1APProtocolIESingleContainer(v *s34.HandoverRequiredIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequiredIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// InitialUEMessageIEValueERABIEContainerListAPERValue is the concrete APERValue[InitialUEMessageIEValueERABIEContainerList].
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

// InitialUEMessageIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{InitialUEMessage-IEs}} of TS 36.413: a single information element field.
type InitialUEMessageIEValueProtocolIESingleContainer = InitialUEMessageIEField

func BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s21.TraceFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeTraceFailureIndicationIEValueCompareS1APProtocolIESingleContainer(v *s21.TraceFailureIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceFailureIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// SONInformationReplyExtIEsExtFieldAPERValue is the concrete APERValue[SONInformationReplyExtIEsExtField].
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

// SONInformationReplyExtIEsExtContainerAPERValue is the concrete APERValue[SONInformationReplyExtIEsExtContainer].
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

// HandoverNotifyIEFieldAPERValue is the concrete APERValue[HandoverNotifyIEField].
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

// InitialUEMessageIEFieldAPERValue is the concrete APERValue[InitialUEMessageIEField].
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

// HandoverNotifyIEContainerAPERValue is the concrete APERValue[HandoverNotifyIEContainer].
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

// InitialUEMessageIEContainerAPERValue is the concrete APERValue[InitialUEMessageIEContainer].
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

// HandoverNotifyIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[HandoverNotifyIEValueProtocolErrorIEContainerList].
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

// InitialUEMessageIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[InitialUEMessageIEValueProtocolErrorIEContainerList].
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

// HandoverNotifyIEValueProtocolIEContainerListAPERValue is the concrete APERValue[HandoverNotifyIEValueProtocolIEContainerList].
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

// InitialUEMessageIEValueProtocolIEContainerListAPERValue is the concrete APERValue[InitialUEMessageIEValueProtocolIEContainerList].
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
					s32.BridgeCaptureS1APTAI(v.rowTAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
					s32.BridgeCompareS1APTAI(v.rowTAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
					s32.BridgeCaptureS1APTAI(v.rowTAI, s)
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
					s28.BridgeCaptureS1APSTMSI(v.rowSTMSI, s)
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
					BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
					s32.BridgeCompareS1APTAI(v.rowTAI, s)
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
					s28.BridgeCompareS1APSTMSI(v.rowSTMSI, s)
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
					BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
					s31.BridgeCaptureS1APSourceNodeID(v.rowSourceNodeID, s)
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
					s31.BridgeCompareS1APSourceNodeID(v.rowSourceNodeID, s)
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

// NewTargetIDTargeteNBID creates a TargetID with the targeteNB-ID alternative.
func BridgeNewTargetIDTargeteNBIDLegacy(v s34.TargeteNBID) s34.TargetID {
	return s34.TargetID{
		Choice:      s00.TargetIDChoiceTargeteNBID,
		TargeteNBID: &v,
	}
}

// NewTargetIDTargetRNCID creates a TargetID with the targetRNC-ID alternative.
func BridgeNewTargetIDTargetRNCIDLegacy(v s34.TargetRNCID) s34.TargetID {
	return s34.TargetID{
		Choice:      s00.TargetIDChoiceTargetRNCID,
		TargetRNCID: &v,
	}
}

// NewTargetIDCGI creates a TargetID with the cGI alternative.
func BridgeNewTargetIDCGILegacy(v s14.CGI) s34.TargetID {
	return s34.TargetID{
		Choice: s00.TargetIDChoiceCGI,
		CGI:    &v,
	}
}

// NewTargetIDTargetgNgRanNodeID creates a TargetID with the targetgNgRanNode-ID alternative.
func BridgeNewTargetIDTargetgNgRanNodeIDLegacy(v s34.TargetNgRanNodeID) s34.TargetID {
	return s34.TargetID{
		Choice:             s00.TargetIDChoiceTargetgNgRanNodeID,
		TargetgNgRanNodeID: &v,
	}
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
	IEExtensions          s12.TunnelInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	bb.EnterComponent("TimeSynchronisationInfo")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TimeSynchronisationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TimeSynchronisationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTimeSynchronisationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	bb.EnterComponent("TimeBasedHandoverInformation")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s11.TimeBasedHandoverInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TimeBasedHandoverInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s11.BridgeTimeBasedHandoverInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
				if err := s12.BridgeTunnelInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("TunnelInformation")
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
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.TunnelInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.TunnelInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeTunnelInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// NewTargetIDTargeteNBID constructs a checked complete value.
func NewTargetIDTargeteNBID(v s34.TargeteNBID, options ...aper.BuildOption) (s34.TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	value := BridgeNewTargetIDTargeteNBIDLegacy(v)
	if _, err := s34.BridgeTargetIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargeteNBID")
	}
	return value, aper.OperationError(nil, "TargetIDTargeteNBID")
}

// NewTargetIDTargetRNCID constructs a checked complete value.
func NewTargetIDTargetRNCID(v s34.TargetRNCID, options ...aper.BuildOption) (s34.TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	value := BridgeNewTargetIDTargetRNCIDLegacy(v)
	if _, err := s34.BridgeTargetIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetRNCID")
	}
	return value, aper.OperationError(nil, "TargetIDTargetRNCID")
}

// NewTargetIDCGI constructs a checked complete value.
func NewTargetIDCGI(v s14.CGI, options ...aper.BuildOption) (s34.TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	value := BridgeNewTargetIDCGILegacy(v)
	if _, err := s34.BridgeTargetIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDCGI")
	}
	return value, aper.OperationError(nil, "TargetIDCGI")
}

// NewTargetIDTargetgNgRanNodeID constructs a checked complete value.
func NewTargetIDTargetgNgRanNodeID(v s34.TargetNgRanNodeID, options ...aper.BuildOption) (s34.TargetID, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	value := BridgeNewTargetIDTargetgNgRanNodeIDLegacy(v)
	if _, err := s34.BridgeTargetIDMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s34.TargetID{}, aper.OperationError(err, "TargetIDTargetgNgRanNodeID")
	}
	return value, aper.OperationError(nil, "TargetIDTargetgNgRanNodeID")
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
	ProtocolIEs      s34.HandoverRequiredIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
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
	ProtocolIEs      s21.TraceFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
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
			if err := s34.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("HandoverRequired")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s34.HandoverRequiredIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s34.HandoverRequiredIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s34.BridgeHandoverRequiredIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s21.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	bb.EnterComponent("TraceFailureIndication")
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
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s21.TraceFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s21.TraceFailureIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s21.BridgeTraceFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	rowSourceNodeID                        *s31.SourceNodeID
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
func (v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) AsSourceNodeID() (*s31.SourceNodeID, bool) {
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
		var value s31.SourceNodeID
		child := scope
		if err := s31.BridgeSourceNodeIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SourceNodeID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SourceNodeID")
		if err != nil {
			return out, err
		}
		*s31.BridgeSourceNodeIDFieldPerPadding(&value) = padding.Padding()
		*s31.BridgeSourceNodeIDFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeSourceNodeIDFieldReceivedBytes(&value))
		*s31.BridgeSourceNodeIDFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s31.BridgeSourceNodeIDMethodMarshalAPERBudget(v.rowSourceNodeID, budget, fresh)
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

type HandoverNotifyIEValue struct {
	id                         s00.ProtocolIEID
	received                   aper.WireSpan
	replay                     aper.Snapshot
	opaque                     aper.OpaqueOpenType
	isOpaque                   bool
	rowMMEUES1APID             *s00.MMEUES1APID
	rowENBUES1APID             *s00.ENBUES1APID
	rowEUTRANCGI               *s17.EUTRANCGI
	rowTAI                     *s32.TAI
	rowTunnelInformationForBBF *TunnelInformation
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

// Opaque returns the retained opaque open value of HandoverNotifyIEValue and reports whether the opaque alternative is selected.
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

// AsMMEUES1APID returns the selected MMEUES1APID value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsTAI returns the selected TAI value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsTAI() (*s32.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsTunnelInformationForBBF returns the selected TunnelInformationForBBF value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsTunnelInformationForBBF() (*TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}

// AsLHNID returns the selected LHNID value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}

// AsPSCellInformation returns the selected PSCellInformation value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsPSCellInformation() (*s20.PSCellInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(288) || v.rowPSCellInformation == nil {
		return nil, false
	}
	return v.rowPSCellInformation, true
}

// AsNotifySourceeNB returns the selected NotifySourceeNB value of HandoverNotifyIEValue and reports whether that alternative is active.
func (v *HandoverNotifyIEValue) AsNotifySourceeNB() (*s00.NotifySourceeNB, bool) {
	if v == nil || v.id != s00.ProtocolIEID(320) || v.rowNotifySourceeNB == nil {
		return nil, false
	}
	return v.rowNotifySourceeNB, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of HandoverNotifyIEValue and reports whether that alternative is active.
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
	case s00.ProtocolIEID(176):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value TunnelInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
		candidate, err := s32.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
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
		candidate, err := v.rowTunnelInformationForBBF.marshalAPERBudget(budget, fresh)
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
	rowTAI                                     *s32.TAI
	rowEUTRANCGI                               *s17.EUTRANCGI
	rowRRCEstablishmentCause                   *s00.RRCEstablishmentCause
	rowSTMSI                                   *s28.STMSI
	rowCSGId                                   *s00.CSGId
	rowGUMMEIID                                *s18.GUMMEI
	rowCellAccessMode                          *s00.CellAccessMode
	rowGWTransportLayerAddress                 *s00.TransportLayerAddress
	rowRelayNodeIndicator                      *s00.RelayNodeIndicator
	rowGUMMEIType                              *s00.GUMMEIType
	rowTunnelInformationForBBF                 *TunnelInformation
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

// Opaque returns the retained opaque open value of InitialUEMessageIEValue and reports whether the opaque alternative is selected.
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

// AsENBUES1APID returns the selected ENBUES1APID value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsNASPDU returns the selected NASPDU value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsNASPDU() (*s00.NASPDU, bool) {
	if v == nil || v.id != s00.ProtocolIEID(26) || v.rowNASPDU == nil {
		return nil, false
	}
	return v.rowNASPDU, true
}

// AsTAI returns the selected TAI value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsTAI() (*s32.TAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(67) || v.rowTAI == nil {
		return nil, false
	}
	return v.rowTAI, true
}

// AsEUTRANCGI returns the selected EUTRANCGI value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsEUTRANCGI() (*s17.EUTRANCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(100) || v.rowEUTRANCGI == nil {
		return nil, false
	}
	return v.rowEUTRANCGI, true
}

// AsRRCEstablishmentCause returns the selected RRCEstablishmentCause value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsRRCEstablishmentCause() (*s00.RRCEstablishmentCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(134) || v.rowRRCEstablishmentCause == nil {
		return nil, false
	}
	return v.rowRRCEstablishmentCause, true
}

// AsSTMSI returns the selected STMSI value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsSTMSI() (*s28.STMSI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(96) || v.rowSTMSI == nil {
		return nil, false
	}
	return v.rowSTMSI, true
}

// AsCSGId returns the selected CSGId value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsCSGId() (*s00.CSGId, bool) {
	if v == nil || v.id != s00.ProtocolIEID(127) || v.rowCSGId == nil {
		return nil, false
	}
	return v.rowCSGId, true
}

// AsGUMMEIID returns the selected GUMMEIID value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsGUMMEIID() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(75) || v.rowGUMMEIID == nil {
		return nil, false
	}
	return v.rowGUMMEIID, true
}

// AsCellAccessMode returns the selected CellAccessMode value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsCellAccessMode() (*s00.CellAccessMode, bool) {
	if v == nil || v.id != s00.ProtocolIEID(145) || v.rowCellAccessMode == nil {
		return nil, false
	}
	return v.rowCellAccessMode, true
}

// AsGWTransportLayerAddress returns the selected GWTransportLayerAddress value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(155) || v.rowGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowGWTransportLayerAddress, true
}

// AsRelayNodeIndicator returns the selected RelayNodeIndicator value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsRelayNodeIndicator() (*s00.RelayNodeIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(160) || v.rowRelayNodeIndicator == nil {
		return nil, false
	}
	return v.rowRelayNodeIndicator, true
}

// AsGUMMEIType returns the selected GUMMEIType value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsGUMMEIType() (*s00.GUMMEIType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(170) || v.rowGUMMEIType == nil {
		return nil, false
	}
	return v.rowGUMMEIType, true
}

// AsTunnelInformationForBBF returns the selected TunnelInformationForBBF value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsTunnelInformationForBBF() (*TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}

// AsSIPTOLGWTransportLayerAddress returns the selected SIPTOLGWTransportLayerAddress value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsSIPTOLGWTransportLayerAddress() (*s00.TransportLayerAddress, bool) {
	if v == nil || v.id != s00.ProtocolIEID(184) || v.rowSIPTOLGWTransportLayerAddress == nil {
		return nil, false
	}
	return v.rowSIPTOLGWTransportLayerAddress, true
}

// AsLHNID returns the selected LHNID value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsLHNID() (*s00.LHNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(186) || v.rowLHNID == nil {
		return nil, false
	}
	return v.rowLHNID, true
}

// AsMMEGroupID returns the selected MMEGroupID value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsMMEGroupID() (*s00.MMEGroupID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(223) || v.rowMMEGroupID == nil {
		return nil, false
	}
	return v.rowMMEGroupID, true
}

// AsUEUsageType returns the selected UEUsageType value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsUEUsageType() (*s00.UEUsageType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(230) || v.rowUEUsageType == nil {
		return nil, false
	}
	return v.rowUEUsageType, true
}

// AsCEModeBSupportIndicator returns the selected CEModeBSupportIndicator value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsCEModeBSupportIndicator() (*s00.CEModeBSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(242) || v.rowCEModeBSupportIndicator == nil {
		return nil, false
	}
	return v.rowCEModeBSupportIndicator, true
}

// AsDCNID returns the selected DCNID value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsDCNID() (*s00.DCNID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(246) || v.rowDCNID == nil {
		return nil, false
	}
	return v.rowDCNID, true
}

// AsCoverageLevel returns the selected CoverageLevel value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsCoverageLevel() (*s00.CoverageLevel, bool) {
	if v == nil || v.id != s00.ProtocolIEID(250) || v.rowCoverageLevel == nil {
		return nil, false
	}
	return v.rowCoverageLevel, true
}

// AsUEApplicationLayerMeasurementCapability returns the selected UEApplicationLayerMeasurementCapability value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsUEApplicationLayerMeasurementCapability() (*s00.UEApplicationLayerMeasurementCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(263) || v.rowUEApplicationLayerMeasurementCapability == nil {
		return nil, false
	}
	return v.rowUEApplicationLayerMeasurementCapability, true
}

// AsEDTSession returns the selected EDTSession value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsEDTSession() (*s00.EDTSession, bool) {
	if v == nil || v.id != s00.ProtocolIEID(281) || v.rowEDTSession == nil {
		return nil, false
	}
	return v.rowEDTSession, true
}

// AsIABNodeIndication returns the selected IABNodeIndication value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsIABNodeIndication() (*s00.IABNodeIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(302) || v.rowIABNodeIndication == nil {
		return nil, false
	}
	return v.rowIABNodeIndication, true
}

// AsLTENTNTAIInformation returns the selected LTENTNTAIInformation value of InitialUEMessageIEValue and reports whether that alternative is active.
func (v *InitialUEMessageIEValue) AsLTENTNTAIInformation() (*s18.LTENTNTAIInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(339) || v.rowLTENTNTAIInformation == nil {
		return nil, false
	}
	return v.rowLTENTNTAIInformation, true
}

// AsCoarseUELocationRequested returns the selected CoarseUELocationRequested value of InitialUEMessageIEValue and reports whether that alternative is active.
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
		var value TunnelInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
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
		candidate, err := s32.BridgeTAIMethodMarshalAPERBudget(v.rowTAI, budget, fresh)
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
		candidate, err := s28.BridgeSTMSIMethodMarshalAPERBudget(v.rowSTMSI, budget, fresh)
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
		candidate, err := v.rowTunnelInformationForBBF.marshalAPERBudget(budget, fresh)
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
			raw.BudgetBuffer().EnterComponent("TimeSynchronisationInfo")
			var zero SONInformationReplyExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(149), raw)
			if err != nil {
				var empty TimeSynchronisationInfo
				return empty, runtime.WrapDecodePath(err, "TimeSynchronisationInfo")
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
			raw.BudgetBuffer().EnterComponent("MutingPatternInformation")
			var zero SONInformationReplyExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(208), raw)
			if err != nil {
				var empty s19.MutingPatternInformation
				return empty, runtime.WrapDecodePath(err, "MutingPatternInformation")
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
			raw.BudgetBuffer().EnterComponent("S1APIEsMobilityInformation")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(175), raw)
			if err != nil {
				var empty s00.S1APIEsMobilityInformation
				return empty, runtime.WrapDecodePath(err, "S1APIEsMobilityInformation")
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
			raw.BudgetBuffer().EnterComponent("UEHistoryInformationFromTheUE")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(194), raw)
			if err != nil {
				var empty s00.UEHistoryInformationFromTheUE
				return empty, runtime.WrapDecodePath(err, "UEHistoryInformationFromTheUE")
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
			raw.BudgetBuffer().EnterComponent("IMSvoiceEPSfallbackfrom5G")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(296), raw)
			if err != nil {
				var empty s00.IMSvoiceEPSfallbackfrom5G
				return empty, runtime.WrapDecodePath(err, "IMSvoiceEPSfallbackfrom5G")
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
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
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
			raw.BudgetBuffer().EnterComponent("ContextatSource")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(300), raw)
			if err != nil {
				var empty s19.ContextatSource
				return empty, runtime.WrapDecodePath(err, "ContextatSource")
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
			raw.BudgetBuffer().EnterComponent("IntersystemMeasurementConfiguration")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(311), raw)
			if err != nil {
				var empty s24.IntersystemMeasurementConfiguration
				return empty, runtime.WrapDecodePath(err, "IntersystemMeasurementConfiguration")
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
	return SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding{info: t.infoSourceNodeID(), codec: func() s31.SourceNodeIDValueCodec {
		sealed := s31.SourceNodeIDValueCodec{}
		*s31.BridgeSourceNodeIDValueCodecFieldPath(&sealed) = "SourceNodeID"
		*s31.BridgeSourceNodeIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SourceNodeID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.SourceNodeID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SourceNodeID")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(312), raw)
			if err != nil {
				var empty s31.SourceNodeID
				return empty, runtime.WrapDecodePath(err, "SourceNodeID")
			}
			value, ok := decoded.AsSourceNodeID()
			if !ok {
				var empty s31.SourceNodeID
				return empty, fmt.Errorf("binding SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs.id-SourceNodeID: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSourceNodeIDValueCodecFieldEncode(&sealed) = func(value s31.SourceNodeID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(312), rowSourceNodeID: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSourceNodeIDValueCodecFieldCapture(&sealed) = func(v s31.SourceNodeID, options aper.DecodeState) (s31.SourceNodeID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APSourceNodeID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSourceNodeIDValueCodecFieldCompare(&sealed) = func(v s31.SourceNodeID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APSourceNodeID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s31.BridgeSourceNodeIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceNodeID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.SourceNodeID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
			return SourceeNBToTargeteNBTransparentContainerExtIEsValue{id: s00.ProtocolIEID(312), rowSourceNodeID: &value}
		}, get: func(value *SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s31.SourceNodeID, bool) {
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
			raw.BudgetBuffer().EnterComponent("EmergencyIndicator")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(326), raw)
			if err != nil {
				var empty s00.EmergencyIndicator
				return empty, runtime.WrapDecodePath(err, "EmergencyIndicator")
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
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(337), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
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
			raw.BudgetBuffer().EnterComponent("GlobalRANNODEID")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(343), raw)
			if err != nil {
				var empty s19.GlobalRANNODEID
				return empty, runtime.WrapDecodePath(err, "GlobalRANNODEID")
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
			raw.BudgetBuffer().EnterComponent("DirectForwardingPathAvailability")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(79), raw)
			if err != nil {
				var empty s00.DirectForwardingPathAvailability
				return empty, runtime.WrapDecodePath(err, "DirectForwardingPathAvailability")
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
			raw.BudgetBuffer().EnterComponent("TimeBasedHandoverInformation")
			var zero SourceeNBToTargeteNBTransparentContainerExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(350), raw)
			if err != nil {
				var empty TimeBasedHandoverInformation
				return empty, runtime.WrapDecodePath(err, "TimeBasedHandoverInformation")
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

type HandoverNotifyIETable struct{}

func HandoverNotifyIEs() HandoverNotifyIETable { return HandoverNotifyIETable{} }

// ID returns the ASN.1 object-set identity of HandoverNotifyIETable.
func (HandoverNotifyIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverNotifyIETable.
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

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
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

// ENBUES1APID returns the typed binding for the ENBUES1APID row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
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

// EUTRANCGI returns the typed binding for the EUTRANCGI row of HandoverNotifyIETable.
func (t HandoverNotifyIETable) EUTRANCGI() HandoverNotifyEUTRANCGIIEBinding {
	return HandoverNotifyEUTRANCGIIEBinding{info: t.infoEUTRANCGI(), codec: func() s18.EUTRANCGIValueCodec {
		sealed := s18.EUTRANCGIValueCodec{}
		*s18.BridgeEUTRANCGIValueCodecFieldPath(&sealed) = "EUTRANCGI"
		*s18.BridgeEUTRANCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.EUTRANCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EUTRANCGI")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(100), raw)
			if err != nil {
				var empty s17.EUTRANCGI
				return empty, runtime.WrapDecodePath(err, "EUTRANCGI")
			}
			value, ok := decoded.AsEUTRANCGI()
			if !ok {
				var empty s17.EUTRANCGI
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-EUTRAN-CGI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeEUTRANCGIValueCodecFieldEncode(&sealed) = func(value s17.EUTRANCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(100), rowEUTRANCGI: &value}).encodeFresh(fresh, budget)
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

// TAI returns the typed binding for the TAI row of HandoverNotifyIETable.
func (t HandoverNotifyIETable) TAI() HandoverNotifyTAIIEBinding {
	return HandoverNotifyTAIIEBinding{info: t.infoTAI(), codec: func() s32.TAIValueCodec {
		sealed := s32.TAIValueCodec{}
		*s32.BridgeTAIValueCodecFieldPath(&sealed) = "TAI"
		*s32.BridgeTAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s32.TAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAI")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(67), raw)
			if err != nil {
				var empty s32.TAI
				return empty, runtime.WrapDecodePath(err, "TAI")
			}
			value, ok := decoded.AsTAI()
			if !ok {
				var empty s32.TAI
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-TAI: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIValueCodecFieldEncode(&sealed) = func(value s32.TAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s32.TAI) HandoverNotifyIEValue {
			return HandoverNotifyIEValue{id: s00.ProtocolIEID(67), rowTAI: &value}
		}, get: func(value *HandoverNotifyIEValue) (*s32.TAI, bool) { return value.AsTAI() }}
}
func (HandoverNotifyIETable) infoTunnelInformationForBBF() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverNotifyIEs().ID(), ID: s00.ProtocolIEID(176), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TunnelInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverNotifyIEs", Row: "id-Tunnel-Information-for-BBF"}}}
}

// TunnelInformationForBBF returns the typed binding for the TunnelInformationForBBF row of HandoverNotifyIETable.
func (t HandoverNotifyIETable) TunnelInformationForBBF() HandoverNotifyTunnelInformationIEBinding {
	return HandoverNotifyTunnelInformationIEBinding{info: t.infoTunnelInformationForBBF(), codec: TunnelInformationValueCodec{path: "TunnelInformation",
		decode: func(data []byte, options aper.DecodeState) (TunnelInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty TunnelInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TunnelInformation")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(176), raw)
			if err != nil {
				var empty TunnelInformation
				return empty, runtime.WrapDecodePath(err, "TunnelInformation")
			}
			value, ok := decoded.AsTunnelInformationForBBF()
			if !ok {
				var empty TunnelInformation
				return empty, fmt.Errorf("binding HandoverNotifyIEs.id-Tunnel-Information-for-BBF: no selected value")
			}
			return *value, nil
		},
		encode: func(value TunnelInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (HandoverNotifyIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}).encodeFresh(fresh, budget)
		}, capture: func(v TunnelInformation, options aper.DecodeState) (TunnelInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APTunnelInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}, compare: func(v TunnelInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APTunnelInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TunnelInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value TunnelInformation) HandoverNotifyIEValue {
		return HandoverNotifyIEValue{id: s00.ProtocolIEID(176), rowTunnelInformationForBBF: &value}
	}, get: func(value *HandoverNotifyIEValue) (*TunnelInformation, bool) {
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

// LHNID returns the typed binding for the LHNID row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("LHNID")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(186), raw)
			if err != nil {
				var empty s00.LHNID
				return empty, runtime.WrapDecodePath(err, "LHNID")
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

// PSCellInformation returns the typed binding for the PSCellInformation row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("PSCellInformation")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(288), raw)
			if err != nil {
				var empty s20.PSCellInformation
				return empty, runtime.WrapDecodePath(err, "PSCellInformation")
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

// NotifySourceeNB returns the typed binding for the NotifySourceeNB row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("NotifySourceeNB")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(320), raw)
			if err != nil {
				var empty s00.NotifySourceeNB
				return empty, runtime.WrapDecodePath(err, "NotifySourceeNB")
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

// LTENTNTAIInformation returns the typed binding for the LTENTNTAIInformation row of HandoverNotifyIETable.
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
			raw.BudgetBuffer().EnterComponent("LTENTNTAIInformation")
			var zero HandoverNotifyIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(339), raw)
			if err != nil {
				var empty s18.LTENTNTAIInformation
				return empty, runtime.WrapDecodePath(err, "LTENTNTAIInformation")
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

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverNotifyIETable.
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

// MutingPatternInformationCodec binds the complete APER value type.
func MutingPatternInformationCodec() s19.MutingPatternInformationValueCodec {
	return SONInformationReplyExtIEs().MutingPatternInformation().Codec()
}

// S1APIEsMobilityInformationCodec binds the complete APER value type.
func S1APIEsMobilityInformationCodec() s01.S1APIEsMobilityInformationValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().MobilityInformation().Codec()
}

// SourceNodeIDCodec binds the complete APER value type.
func SourceNodeIDCodec() s31.SourceNodeIDValueCodec {
	return SourceeNBToTargeteNBTransparentContainerExtIEs().SourceNodeID().Codec()
}

// TargeteNBIDCodec binds the complete source value type.
func TargeteNBIDCodec() s34.TargeteNBIDValueCodec {
	return func() s34.TargeteNBIDValueCodec {
		sealed := s34.TargeteNBIDValueCodec{}
		*s34.BridgeTargeteNBIDValueCodecFieldPath(&sealed) = "TargeteNBID"
		*s34.BridgeTargeteNBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s34.TargeteNBID, error) {
			var value s34.TargeteNBID
			if err := s34.BridgeTargeteNBIDMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
				return s34.TargeteNBID{}, err
			}
			*s34.BridgeTargeteNBIDFieldReceived(&value) = true
			*s34.BridgeTargeteNBIDFieldReceivedAbsolute(&value) = true
			*s34.BridgeTargeteNBIDFieldReceivedBytes(&value) = aper.OriginalWire(data)
			return value, nil
		}
		*s34.BridgeTargeteNBIDValueCodecFieldEncode(&sealed) = func(value s34.TargeteNBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s34.BridgeTargeteNBIDMethodMarshalAPERBudget((&value), budget, fresh)
		}
		*s34.BridgeTargeteNBIDValueCodecFieldCapture(&sealed) = func(v s34.TargeteNBID, options aper.DecodeState) (s34.TargeteNBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s34.BridgeCaptureS1APTargeteNBID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s34.BridgeTargeteNBIDValueCodecFieldCompare(&sealed) = func(v s34.TargeteNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s34.BridgeCompareS1APTargeteNBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s34.BridgeTargeteNBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TargeteNBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

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
func BridgeHandoverNotifyEUTRANCGIIEBindingFieldCodec(v *HandoverNotifyEUTRANCGIIEBinding) *s18.EUTRANCGIValueCodec {
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
func BridgeHandoverNotifyIEValueFieldRowTAI(v *HandoverNotifyIEValue) **s32.TAI { return &v.rowTAI }
func BridgeHandoverNotifyIEValueFieldRowTunnelInformationForBBF(v *HandoverNotifyIEValue) **TunnelInformation {
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
func BridgeHandoverNotifyTAIIEBindingFieldGet(v *HandoverNotifyTAIIEBinding) *func(*HandoverNotifyIEValue) (*s32.TAI, bool) {
	return &v.get
}
func BridgeHandoverNotifyTAIIEBindingFieldInfo(v *HandoverNotifyTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyTAIIEBindingFieldInject(v *HandoverNotifyTAIIEBinding) *func(s32.TAI) HandoverNotifyIEValue {
	return &v.inject
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldCodec(v *HandoverNotifyTunnelInformationIEBinding) *TunnelInformationValueCodec {
	return &v.codec
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldGet(v *HandoverNotifyTunnelInformationIEBinding) *func(*HandoverNotifyIEValue) (*TunnelInformation, bool) {
	return &v.get
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldInfo(v *HandoverNotifyTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverNotifyTunnelInformationIEBindingFieldInject(v *HandoverNotifyTunnelInformationIEBinding) *func(TunnelInformation) HandoverNotifyIEValue {
	return &v.inject
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
func BridgeInitialUEMessageEUTRANCGIIEBindingFieldCodec(v *InitialUEMessageEUTRANCGIIEBinding) *s18.EUTRANCGIValueCodec {
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
func BridgeInitialUEMessageIEValueFieldRowSTMSI(v *InitialUEMessageIEValue) **s28.STMSI {
	return &v.rowSTMSI
}
func BridgeInitialUEMessageIEValueFieldRowTAI(v *InitialUEMessageIEValue) **s32.TAI { return &v.rowTAI }
func BridgeInitialUEMessageIEValueFieldRowTunnelInformationForBBF(v *InitialUEMessageIEValue) **TunnelInformation {
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
func BridgeInitialUEMessageSTMSIIEBindingFieldGet(v *InitialUEMessageSTMSIIEBinding) *func(*InitialUEMessageIEValue) (*s28.STMSI, bool) {
	return &v.get
}
func BridgeInitialUEMessageSTMSIIEBindingFieldInfo(v *InitialUEMessageSTMSIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageSTMSIIEBindingFieldInject(v *InitialUEMessageSTMSIIEBinding) *func(s28.STMSI) InitialUEMessageIEValue {
	return &v.inject
}
func BridgeInitialUEMessageTAIIEBindingFieldCodec(v *InitialUEMessageTAIIEBinding) *s32.TAIValueCodec {
	return &v.codec
}
func BridgeInitialUEMessageTAIIEBindingFieldGet(v *InitialUEMessageTAIIEBinding) *func(*InitialUEMessageIEValue) (*s32.TAI, bool) {
	return &v.get
}
func BridgeInitialUEMessageTAIIEBindingFieldInfo(v *InitialUEMessageTAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageTAIIEBindingFieldInject(v *InitialUEMessageTAIIEBinding) *func(s32.TAI) InitialUEMessageIEValue {
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
func BridgeInitialUEMessageTunnelInformationIEBindingFieldGet(v *InitialUEMessageTunnelInformationIEBinding) *func(*InitialUEMessageIEValue) (*TunnelInformation, bool) {
	return &v.get
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldInfo(v *InitialUEMessageTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialUEMessageTunnelInformationIEBindingFieldInject(v *InitialUEMessageTunnelInformationIEBinding) *func(TunnelInformation) InitialUEMessageIEValue {
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldCodec(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *s31.SourceNodeIDValueCodec {
	return &v.codec
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldGet(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *func(*SourceeNBToTargeteNBTransparentContainerExtIEsValue) (*s31.SourceNodeID, bool) {
	return &v.get
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldInfo(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBindingFieldInject(v *SourceeNBToTargeteNBTransparentContainerExtIEsSourceNodeIDExtBinding) *func(s31.SourceNodeID) SourceeNBToTargeteNBTransparentContainerExtIEsValue {
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
func BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueFieldRowSourceNodeID(v *SourceeNBToTargeteNBTransparentContainerExtIEsValue) **s31.SourceNodeID {
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
func BridgeTunnelInformationValueCodecFieldCapture(v *TunnelInformationValueCodec) *func(TunnelInformation, aper.DecodeState) (TunnelInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeTunnelInformationValueCodecFieldCompare(v *TunnelInformationValueCodec) *func(TunnelInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTunnelInformationValueCodecFieldContext(v *TunnelInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTunnelInformationValueCodecFieldDecode(v *TunnelInformationValueCodec) *func([]byte, aper.DecodeState) (TunnelInformation, error) {
	return &v.decode
}
func BridgeTunnelInformationValueCodecFieldEncode(v *TunnelInformationValueCodec) *func(TunnelInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTunnelInformationValueCodecFieldPath(v *TunnelInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTunnelInformationValueCodecMethodEncodeBudgetValue(v TunnelInformationValueCodec, a0 TunnelInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTunnelInformationValueCodecMethodEncodeChanged(v TunnelInformationValueCodec, a0 TunnelInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *HandoverNotifyIEValue) Selected() (any, bool) {
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
	case 100:
		if value, ok := v.AsEUTRANCGI(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsTAI(); ok {
			return value, true
		}
	case 176:
		if value, ok := v.AsTunnelInformationForBBF(); ok {
			return value, true
		}
	case 186:
		if value, ok := v.AsLHNID(); ok {
			return value, true
		}
	case 288:
		if value, ok := v.AsPSCellInformation(); ok {
			return value, true
		}
	case 320:
		if value, ok := v.AsNotifySourceeNB(); ok {
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
func (v *InitialUEMessageIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 26:
		if value, ok := v.AsNASPDU(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsTAI(); ok {
			return value, true
		}
	case 100:
		if value, ok := v.AsEUTRANCGI(); ok {
			return value, true
		}
	case 134:
		if value, ok := v.AsRRCEstablishmentCause(); ok {
			return value, true
		}
	case 96:
		if value, ok := v.AsSTMSI(); ok {
			return value, true
		}
	case 127:
		if value, ok := v.AsCSGId(); ok {
			return value, true
		}
	case 75:
		if value, ok := v.AsGUMMEIID(); ok {
			return value, true
		}
	case 145:
		if value, ok := v.AsCellAccessMode(); ok {
			return value, true
		}
	case 155:
		if value, ok := v.AsGWTransportLayerAddress(); ok {
			return value, true
		}
	case 160:
		if value, ok := v.AsRelayNodeIndicator(); ok {
			return value, true
		}
	case 170:
		if value, ok := v.AsGUMMEIType(); ok {
			return value, true
		}
	case 176:
		if value, ok := v.AsTunnelInformationForBBF(); ok {
			return value, true
		}
	case 184:
		if value, ok := v.AsSIPTOLGWTransportLayerAddress(); ok {
			return value, true
		}
	case 186:
		if value, ok := v.AsLHNID(); ok {
			return value, true
		}
	case 223:
		if value, ok := v.AsMMEGroupID(); ok {
			return value, true
		}
	case 230:
		if value, ok := v.AsUEUsageType(); ok {
			return value, true
		}
	case 242:
		if value, ok := v.AsCEModeBSupportIndicator(); ok {
			return value, true
		}
	case 246:
		if value, ok := v.AsDCNID(); ok {
			return value, true
		}
	case 250:
		if value, ok := v.AsCoverageLevel(); ok {
			return value, true
		}
	case 263:
		if value, ok := v.AsUEApplicationLayerMeasurementCapability(); ok {
			return value, true
		}
	case 281:
		if value, ok := v.AsEDTSession(); ok {
			return value, true
		}
	case 302:
		if value, ok := v.AsIABNodeIndication(); ok {
			return value, true
		}
	case 339:
		if value, ok := v.AsLTENTNTAIInformation(); ok {
			return value, true
		}
	case 353:
		if value, ok := v.AsCoarseUELocationRequested(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SONInformationReplyExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 149:
		if value, ok := v.AsTimeSynchronisationInfo(); ok {
			return value, true
		}
	case 208:
		if value, ok := v.AsMutingPatternInformation(); ok {
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
