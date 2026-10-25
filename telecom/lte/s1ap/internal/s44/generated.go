// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s44 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s44

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ResetAcknowledgeIEContainer is ProtocolIE-Container {{ResetAcknowledgeIEs}} of TS 36.413: a list of ResetAcknowledgeIEField values.
type ResetAcknowledgeIEContainer []ResetAcknowledgeIEField

// ResetAcknowledgeIEField is ProtocolIE-Field {{ResetAcknowledgeIEs}} of TS 36.413: an information element field.
type ResetAcknowledgeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ResetAcknowledgeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEField) WithoutReplay() ResetAcknowledgeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ResetAcknowledgeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ResetAcknowledgeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ResetAcknowledgeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetAcknowledgeIEField{}
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
	var zero ResetAcknowledgeIEValue

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

// PWSRestartIndicationIEContainer is ProtocolIE-Container {{PWSRestartIndicationIEs}} of TS 36.413: a list of PWSRestartIndicationIEField values.
type PWSRestartIndicationIEContainer []PWSRestartIndicationIEField

// PWSRestartIndicationIEField is ProtocolIE-Field {{PWSRestartIndicationIEs}} of TS 36.413: an information element field.
type PWSRestartIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PWSRestartIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEField) WithoutReplay() PWSRestartIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PWSRestartIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PWSRestartIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *PWSRestartIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PWSRestartIndicationIEField{}
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
	var zero PWSRestartIndicationIEValue

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

// ERABModificationIndicationIEContainer is ProtocolIE-Container {{E-RABModificationIndicationIEs}} of TS 36.413: a list of ERABModificationIndicationIEField values.
type ERABModificationIndicationIEContainer []ERABModificationIndicationIEField

// ERABModificationIndicationIEField is ProtocolIE-Field {{E-RABModificationIndicationIEs}} of TS 36.413: an information element field.
type ERABModificationIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ERABModificationIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEField) WithoutReplay() ERABModificationIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ERABModificationIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ERABModificationIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ERABModificationIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ERABModificationIndicationIEField{}
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
	var zero ERABModificationIndicationIEValue

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
func BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainer(v *PWSRestartIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainer(v *PWSRestartIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(v *ResetAcknowledgeIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(v *ResetAcknowledgeIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(v *s32.UplinkNASTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(v *s32.UplinkNASTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s12.UplinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s12.UplinkNonUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(v *s21.UplinkS1cdma2000tunnellingIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(v *s21.UplinkS1cdma2000tunnellingIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(v *s12.UplinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(v *s12.UplinkUEAssociatedLPPaTransportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s21.UserLocationInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s21.UserLocationInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationMMEUES1APIDIEBinding binds MMEUES1APID to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationMMEUES1APIDIEBinding) Get(field *ERABModificationIndicationIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationENBUES1APIDIEBinding binds ENBUES1APID to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationENBUES1APIDIEBinding) Get(field *ERABModificationIndicationIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding binds ERABToBeModifiedListBearerModInd to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding struct {
	info   s00.FieldInfo
	codec  s17.ERABToBeModifiedListBearerModIndValueCodec
	inject func(s17.ERABToBeModifiedListBearerModInd,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s17.ERABToBeModifiedListBearerModInd,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) Codec() s17.ERABToBeModifiedListBearerModIndValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) New(value s17.ERABToBeModifiedListBearerModInd,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeERABToBeModifiedListBearerModIndValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) Get(field *ERABModificationIndicationIEField) (*s17.ERABToBeModifiedListBearerModInd,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding binds ERABNotToBeModifiedListBearerModInd to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding struct {
	info   s00.FieldInfo
	codec  s16.ERABNotToBeModifiedListBearerModIndValueCodec
	inject func(s16.ERABNotToBeModifiedListBearerModInd,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s16.ERABNotToBeModifiedListBearerModInd,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) Codec() s16.ERABNotToBeModifiedListBearerModIndValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) New(value s16.ERABNotToBeModifiedListBearerModInd,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s16.BridgeERABNotToBeModifiedListBearerModIndValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) Get(field *ERABModificationIndicationIEField) (*s16.ERABNotToBeModifiedListBearerModInd,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationCSGMembershipInfoIEBinding binds CSGMembershipInfo to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationCSGMembershipInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CSGMembershipInfoValueCodec
	inject func(s14.CSGMembershipInfo,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s14.CSGMembershipInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationCSGMembershipInfoIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationCSGMembershipInfoIEBinding) Codec() s14.CSGMembershipInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationCSGMembershipInfoIEBinding) New(value s14.CSGMembershipInfo,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCSGMembershipInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationCSGMembershipInfoIEBinding) Get(field *ERABModificationIndicationIEField) (*s14.CSGMembershipInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationTunnelInformationIEBinding binds TunnelInformation to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationTunnelInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s35.TunnelInformationValueCodec
	inject func(s35.TunnelInformation,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s35.TunnelInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationTunnelInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationTunnelInformationIEBinding) Codec() s35.TunnelInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationTunnelInformationIEBinding) New(value s35.TunnelInformation,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s35.BridgeTunnelInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationTunnelInformationIEBinding) Get(field *ERABModificationIndicationIEField) (*s35.TunnelInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding binds SecondaryRATDataUsageReportList to the E-RABModificationIndicationIEs object set of TS 36.413.
type ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding struct {
	info   s00.FieldInfo
	codec  s28.SecondaryRATDataUsageReportListValueCodec
	inject func(s28.SecondaryRATDataUsageReportList,

	) ERABModificationIndicationIEValue

	get func(*ERABModificationIndicationIEValue,

	) (*s28.SecondaryRATDataUsageReportList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) Codec() s28.SecondaryRATDataUsageReportListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) New(value s28.SecondaryRATDataUsageReportList,

) (ERABModificationIndicationIEField, error) {
	if b.inject == nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s28.BridgeSecondaryRATDataUsageReportListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ERABModificationIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ERABModificationIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) Get(field *ERABModificationIndicationIEField) (*s28.SecondaryRATDataUsageReportList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationECGIListForRestartIEBinding binds ECGIListForRestart to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationECGIListForRestartIEBinding struct {
	info   s00.FieldInfo
	codec  s17.ECGIListForRestartValueCodec
	inject func(s17.ECGIListForRestart,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s17.ECGIListForRestart,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Codec() s17.ECGIListForRestartValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationECGIListForRestartIEBinding) New(value s17.ECGIListForRestart,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeECGIListForRestartValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationECGIListForRestartIEBinding) Get(field *PWSRestartIndicationIEField) (*s17.ECGIListForRestart,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationGlobalENBIDIEBinding binds GlobalENBID to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationGlobalENBIDIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GlobalENBIDValueCodec
	inject func(s18.GlobalENBID,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s18.GlobalENBID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Codec() s18.GlobalENBIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationGlobalENBIDIEBinding) New(value s18.GlobalENBID,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGlobalENBIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationGlobalENBIDIEBinding) Get(field *PWSRestartIndicationIEField) (*s18.GlobalENBID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationTAIListForRestartIEBinding binds TAIListForRestart to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationTAIListForRestartIEBinding struct {
	info   s00.FieldInfo
	codec  s32.TAIListForRestartValueCodec
	inject func(s32.TAIListForRestart,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s32.TAIListForRestart,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Codec() s32.TAIListForRestartValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationTAIListForRestartIEBinding) New(value s32.TAIListForRestart,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeTAIListForRestartValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationTAIListForRestartIEBinding) Get(field *PWSRestartIndicationIEField) (*s32.TAIListForRestart,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding binds EmergencyAreaIDListForRestart to the PWSRestartIndicationIEs object set of TS 36.413.
type PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EmergencyAreaIDListForRestartValueCodec
	inject func(s00.EmergencyAreaIDListForRestart,

	) PWSRestartIndicationIEValue

	get func(*PWSRestartIndicationIEValue,

	) (*s00.EmergencyAreaIDListForRestart,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) Codec() s00.EmergencyAreaIDListForRestartValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) New(value s00.EmergencyAreaIDListForRestart,

) (PWSRestartIndicationIEField, error) {
	if b.inject == nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PWSRestartIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return PWSRestartIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) Get(field *PWSRestartIndicationIEField) (*s00.EmergencyAreaIDListForRestart,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding binds UEAssociatedLogicalS1ConnectionListResAck to the ResetAcknowledgeIEs object set of TS 36.413.
type ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding struct {
	info   s00.FieldInfo
	codec  s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec
	inject func(s36.UEAssociatedLogicalS1ConnectionListResAck,

	) ResetAcknowledgeIEValue

	get func(*ResetAcknowledgeIEValue,

	) (*s36.UEAssociatedLogicalS1ConnectionListResAck,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Codec() s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) New(value s36.UEAssociatedLogicalS1ConnectionListResAck,

) (ResetAcknowledgeIEField, error) {
	if b.inject == nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) Get(field *ResetAcknowledgeIEField) (*s36.UEAssociatedLogicalS1ConnectionListResAck,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetAcknowledgeCriticalityDiagnosticsIEBinding binds CriticalityDiagnostics to the ResetAcknowledgeIEs object set of TS 36.413.
type ResetAcknowledgeCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s22.CriticalityDiagnosticsValueCodec
	inject func(s22.CriticalityDiagnostics,

	) ResetAcknowledgeIEValue

	get func(*ResetAcknowledgeIEValue,

	) (*s22.CriticalityDiagnostics,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Codec() s22.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) New(value s22.CriticalityDiagnostics,

) (ResetAcknowledgeIEField, error) {
	if b.inject == nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetAcknowledgeIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetAcknowledgeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetAcknowledgeCriticalityDiagnosticsIEBinding) Get(field *ResetAcknowledgeIEField) (*s22.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PWSRestartIndicationValueCodec is the concrete ValueCodec[PWSRestartIndication].
type PWSRestartIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndication,

		error)
	encode func(PWSRestartIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndication, aper.DecodeState,

	) (PWSRestartIndication, aper.Snapshot,

	)
	compare func(PWSRestartIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationValueCodec) New(value PWSRestartIndication,

) (PWSRestartIndicationAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationValueCodec) EncodeAPER(value PWSRestartIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationValueCodec) encodeBudgetValue(value PWSRestartIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationValueCodec) encodeChanged(value PWSRestartIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeValueCodec is the concrete ValueCodec[ResetAcknowledge].
type ResetAcknowledgeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledge,

		error)
	encode func(ResetAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledge, aper.DecodeState,

	) (ResetAcknowledge, aper.Snapshot,

	)
	compare func(ResetAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeValueCodec) New(value ResetAcknowledge,

) (ResetAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeValueCodec) EncodeAPER(value ResetAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeValueCodec) encodeBudgetValue(value ResetAcknowledge,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeValueCodec) encodeChanged(value ResetAcknowledge,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1SetupRequestValueCodec is the concrete ValueCodec[S1SetupRequest].
type S1SetupRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (S1SetupRequest,

		error)
	encode func(S1SetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(S1SetupRequest, aper.DecodeState,

	) (S1SetupRequest, aper.Snapshot,

	)
	compare func(S1SetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1SetupRequestValueCodec) New(value S1SetupRequest,

) (S1SetupRequestAPERValue, error) {
	if c.encode == nil {
		return S1SetupRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1SetupRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1SetupRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1SetupRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1SetupRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1SetupRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1SetupRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1SetupRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1SetupRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1SetupRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1SetupRequestValueCodec) EncodeAPER(value S1SetupRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1SetupRequestValueCodec) encodeBudgetValue(value S1SetupRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1SetupRequestValueCodec) encodeChanged(value S1SetupRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNASTransportValueCodec is the concrete ValueCodec[UplinkNASTransport].
type UplinkNASTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNASTransport,

		error)
	encode func(UplinkNASTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNASTransport, aper.DecodeState,

	) (UplinkNASTransport, aper.Snapshot,

	)
	compare func(UplinkNASTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNASTransportValueCodec) New(value UplinkNASTransport,

) (UplinkNASTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNASTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNASTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNASTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNASTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNASTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNASTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNASTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNASTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNASTransportValueCodec) EncodeAPER(value UplinkNASTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkNASTransportValueCodec) encodeBudgetValue(value UplinkNASTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNASTransportValueCodec) encodeChanged(value UplinkNASTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkNonUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport,

		error)
	encode func(UplinkNonUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkNonUEAssociatedLPPaTransport, aper.DecodeState,

	) (UplinkNonUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) New(value UplinkNonUEAssociatedLPPaTransport,

) (UplinkNonUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkNonUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkNonUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkNonUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkNonUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkNonUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkNonUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) EncodeAPER(value UplinkNonUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value UplinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkNonUEAssociatedLPPaTransportValueCodec) encodeChanged(value UplinkNonUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkS1cdma2000tunnellingValueCodec is the concrete ValueCodec[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnelling,

		error)
	encode func(UplinkS1cdma2000tunnelling,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkS1cdma2000tunnelling, aper.DecodeState,

	) (UplinkS1cdma2000tunnelling, aper.Snapshot,

	)
	compare func(UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkS1cdma2000tunnellingValueCodec) New(value UplinkS1cdma2000tunnelling,

) (UplinkS1cdma2000tunnellingAPERValue, error) {
	if c.encode == nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkS1cdma2000tunnellingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkS1cdma2000tunnellingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkS1cdma2000tunnellingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkS1cdma2000tunnellingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkS1cdma2000tunnellingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkS1cdma2000tunnellingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkS1cdma2000tunnellingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkS1cdma2000tunnellingValueCodec) EncodeAPER(value UplinkS1cdma2000tunnellingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkS1cdma2000tunnellingValueCodec) encodeBudgetValue(value UplinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkS1cdma2000tunnellingValueCodec) encodeChanged(value UplinkS1cdma2000tunnelling,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UplinkUEAssociatedLPPaTransportValueCodec is the concrete ValueCodec[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UplinkUEAssociatedLPPaTransport,

		error)
	encode func(UplinkUEAssociatedLPPaTransport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UplinkUEAssociatedLPPaTransport, aper.DecodeState,

	) (UplinkUEAssociatedLPPaTransport, aper.Snapshot,

	)
	compare func(UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UplinkUEAssociatedLPPaTransportValueCodec) New(value UplinkUEAssociatedLPPaTransport,

) (UplinkUEAssociatedLPPaTransportAPERValue, error) {
	if c.encode == nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UplinkUEAssociatedLPPaTransportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UplinkUEAssociatedLPPaTransportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UplinkUEAssociatedLPPaTransportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UplinkUEAssociatedLPPaTransportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UplinkUEAssociatedLPPaTransportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UplinkUEAssociatedLPPaTransportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UplinkUEAssociatedLPPaTransportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UplinkUEAssociatedLPPaTransportValueCodec) EncodeAPER(value UplinkUEAssociatedLPPaTransportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UplinkUEAssociatedLPPaTransportValueCodec) encodeBudgetValue(value UplinkUEAssociatedLPPaTransport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UplinkUEAssociatedLPPaTransportValueCodec) encodeChanged(value UplinkUEAssociatedLPPaTransport,

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
func BridgeUplinkNASTransportIEValueValidateS1APIEContainer(fields s32.UplinkNASTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s32.BridgeUplinkNASTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeUplinkNASTransportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeUplinkNASTransportIEValueMethodRule(field.Value).Assignment
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
func BridgeResetAcknowledgeIEValueValidateS1APIEContainer(fields ResetAcknowledgeIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
func BridgeS1SetupRequestIEValueValidateS1APIEContainer(fields s43.S1SetupRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s43.BridgeS1SetupRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s43.BridgeS1SetupRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s43.BridgeS1SetupRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields s21.UplinkS1cdma2000tunnellingIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodRule(field.Value).Assignment
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
func BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields s12.UplinkUEAssociatedLPPaTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodRule(field.Value).Assignment
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
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields s12.UplinkNonUEAssociatedLPPaTransportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodRule(field.Value).Assignment
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
func BridgePWSRestartIndicationIEValueValidateS1APIEContainer(fields PWSRestartIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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

// PWSRestartIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueERABIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEValueERABIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSRestartIndicationIEValueERABIEContainerListValueCodec{}
	}
	return PWSRestartIndicationIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSRestartIndicationIEValueERABIEContainerList(value), err
	}, encode: func(value PWSRestartIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueERABIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
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

// ResetAcknowledgeIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueERABIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEValueERABIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetAcknowledgeIEValueERABIEContainerListValueCodec{}
	}
	return ResetAcknowledgeIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetAcknowledgeIEValueERABIEContainerList(value), err
	}, encode: func(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueERABIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APERABIEContainerList(&v, &s)
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

// S1SetupRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueERABIEContainerListCodec(table s00.S1SetupRequestIEValueIETable) s43.S1SetupRequestIEValueERABIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s43.S1SetupRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s43.S1SetupRequestIEValueERABIEContainerListValueCodec {
		sealed := s43.S1SetupRequestIEValueERABIEContainerListValueCodec{}
		*s43.BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.S1SetupRequestIEValueERABIEContainerList, error) {
			value, err := (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s43.S1SetupRequestIEValueERABIEContainerList(value), err
		}
		*s43.BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s43.S1SetupRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldEncode(&codec))(s43.S1SetupRequestIEContainer(value), fresh, budget)
		}
		*s43.BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s43.S1SetupRequestIEValueERABIEContainerList, options aper.DecodeState) (s43.S1SetupRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s43.BridgeS1SetupRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s43.BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s43.S1SetupRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeS1SetupRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeS1SetupRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNASTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueERABIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable) s32.UplinkNASTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.UplinkNASTransportIEValueERABIEContainerListValueCodec{}
	}
	return func() s32.UplinkNASTransportIEValueERABIEContainerListValueCodec {
		sealed := s32.UplinkNASTransportIEValueERABIEContainerListValueCodec{}
		*s32.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.UplinkNASTransportIEValueERABIEContainerList, error) {
			value, err := (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.UplinkNASTransportIEValueERABIEContainerList(value), err
		}
		*s32.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.UplinkNASTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s32.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s32.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.UplinkNASTransportIEValueERABIEContainerList, options aper.DecodeState) (s32.UplinkNASTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.UplinkNASTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeUplinkNASTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	return func() s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			value, err := (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList(value), err
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueERABIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{}
	}
	return func() s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec {
		sealed := s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodec{}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, error) {
			value, err := (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList(value), err
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s21.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
	}
	return func() s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec {
		sealed := s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, error) {
			value, err := (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList(value), err
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UserLocationInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UserLocationInformation-ExtIEs}} codec of TS 36.413.
func UserLocationInformationExtIEsValueExtensionFieldTableCodec(table s00.UserLocationInformationExtIEsValueExtensionTable) s21.UserLocationInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeUserLocationInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s21.UserLocationInformationExtIEsExtFieldValueCodec{}
	}
	return func() s21.UserLocationInformationExtIEsExtFieldValueCodec {
		sealed := s21.UserLocationInformationExtIEsExtFieldValueCodec{}
		*s21.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UserLocationInformationExtIEsExtField, error) {
			var field s21.UserLocationInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s21.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s21.UserLocationInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s21.UserLocationInformationExtIEsExtField, options aper.DecodeState) (s21.UserLocationInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s21.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s21.UserLocationInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUserLocationInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueIEFieldTableCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEFieldValueCodec {
	if !*s00.BridgePWSRestartIndicationIEValueIETableFieldBound(&table) {
		return PWSRestartIndicationIEFieldValueCodec{}
	}
	return PWSRestartIndicationIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEField, error) {
		var field PWSRestartIndicationIEField
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
	}, encode: func(field PWSRestartIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PWSRestartIndicationIEField, options aper.DecodeState) (PWSRestartIndicationIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PWSRestartIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APProtocolIEField(&v, &s)
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

// ResetAcknowledgeIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueIEFieldTableCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEFieldValueCodec {
	if !*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&table) {
		return ResetAcknowledgeIEFieldValueCodec{}
	}
	return ResetAcknowledgeIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEField, error) {
		var field ResetAcknowledgeIEField
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
	}, encode: func(field ResetAcknowledgeIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ResetAcknowledgeIEField, options aper.DecodeState) (ResetAcknowledgeIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ResetAcknowledgeIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(&v, &s)
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

// UplinkNASTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueIEFieldTableCodec(table s00.UplinkNASTransportIEValueIETable) s32.UplinkNASTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkNASTransportIEValueIETableFieldBound(&table) {
		return s32.UplinkNASTransportIEFieldValueCodec{}
	}
	return func() s32.UplinkNASTransportIEFieldValueCodec {
		sealed := s32.UplinkNASTransportIEFieldValueCodec{}
		*s32.BridgeUplinkNASTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.UplinkNASTransportIEField, error) {
			var field s32.UplinkNASTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s32.BridgeUplinkNASTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s32.UplinkNASTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeUplinkNASTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s32.UplinkNASTransportIEField, options aper.DecodeState) (s32.UplinkNASTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s32.BridgeUplinkNASTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s32.UplinkNASTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeUplinkNASTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s12.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s12.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s12.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s12.UplinkNonUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEField, error) {
			var field s12.UplinkNonUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UplinkNonUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueIEFieldTableCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s21.UplinkS1cdma2000tunnellingIEFieldValueCodec {
	if !*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return s21.UplinkS1cdma2000tunnellingIEFieldValueCodec{}
	}
	return func() s21.UplinkS1cdma2000tunnellingIEFieldValueCodec {
		sealed := s21.UplinkS1cdma2000tunnellingIEFieldValueCodec{}
		*s21.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEField, error) {
			var field s21.UplinkS1cdma2000tunnellingIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldEncode(&sealed) = func(field s21.UplinkS1cdma2000tunnellingIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCapture(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEField, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldCompare(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueIEFieldTableCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s12.UplinkUEAssociatedLPPaTransportIEFieldValueCodec {
	if !*s00.BridgeUplinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s12.UplinkUEAssociatedLPPaTransportIEFieldValueCodec{}
	}
	return func() s12.UplinkUEAssociatedLPPaTransportIEFieldValueCodec {
		sealed := s12.UplinkUEAssociatedLPPaTransportIEFieldValueCodec{}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEField, error) {
			var field s12.UplinkUEAssociatedLPPaTransportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UplinkUEAssociatedLPPaTransportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEField, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueIETableCodec(table s00.PWSRestartIndicationIEValueIETable, bounds aper.ListBounds) PWSRestartIndicationIEContainerValueCodec {
	if !*s00.BridgePWSRestartIndicationIEValueIETableFieldBound(&table) {
		return PWSRestartIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PWSRestartIndicationIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PWSRestartIndicationIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PWSRestartIndicationIEField
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
		encode: func(fields PWSRestartIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v PWSRestartIndicationIEContainer, options aper.DecodeState) (PWSRestartIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v PWSRestartIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// ResetAcknowledgeIEValueIETableCodec constructs the ProtocolIE-Container {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueIETableCodec(table s00.ResetAcknowledgeIEValueIETable, bounds aper.ListBounds) ResetAcknowledgeIEContainerValueCodec {
	if !*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&table) {
		return ResetAcknowledgeIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ResetAcknowledgeIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetAcknowledgeIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetAcknowledgeIEField
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
		encode: func(fields ResetAcknowledgeIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ResetAcknowledgeIEContainer, options aper.DecodeState) (ResetAcknowledgeIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ResetAcknowledgeIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// S1SetupRequestIEValueIETableCodec constructs the ProtocolIE-Container {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueIETableCodec(table s00.S1SetupRequestIEValueIETable, bounds aper.ListBounds) s43.S1SetupRequestIEContainerValueCodec {
	if !*s00.BridgeS1SetupRequestIEValueIETableFieldBound(&table) {
		return s43.S1SetupRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s43.S1SetupRequestIEContainerValueCodec {
		sealed := s43.S1SetupRequestIEContainerValueCodec{}
		*s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.S1SetupRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s43.S1SetupRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s43.S1SetupRequestIEField
					if err := s43.BridgeS1SetupRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s43.BridgeS1SetupRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s43.S1SetupRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s43.BridgeS1SetupRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s43.BridgeS1SetupRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s43.S1SetupRequestIEContainer, options aper.DecodeState) (s43.S1SetupRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s43.BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s43.BridgeS1SetupRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s43.S1SetupRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s43.BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeS1SetupRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNASTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueIETableCodec(table s00.UplinkNASTransportIEValueIETable, bounds aper.ListBounds) s32.UplinkNASTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkNASTransportIEValueIETableFieldBound(&table) {
		return s32.UplinkNASTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.UplinkNASTransportIEContainerValueCodec {
		sealed := s32.UplinkNASTransportIEContainerValueCodec{}
		*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.UplinkNASTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.UplinkNASTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.UplinkNASTransportIEField
					if err := s32.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.UplinkNASTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s32.UplinkNASTransportIEContainer, options aper.DecodeState) (s32.UplinkNASTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s32.UplinkNASTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s12.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkNonUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s12.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s12.UplinkNonUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UplinkNonUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UplinkNonUEAssociatedLPPaTransportIEField
					if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UplinkNonUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueIETableCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) s21.UplinkS1cdma2000tunnellingIEContainerValueCodec {
	if !*s00.BridgeUplinkS1cdma2000tunnellingIEValueIETableFieldBound(&table) {
		return s21.UplinkS1cdma2000tunnellingIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.UplinkS1cdma2000tunnellingIEContainerValueCodec {
		sealed := s21.UplinkS1cdma2000tunnellingIEContainerValueCodec{}
		*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UplinkS1cdma2000tunnellingIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UplinkS1cdma2000tunnellingIEField
					if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&sealed) = func(fields s21.UplinkS1cdma2000tunnellingIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCapture(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEContainer, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldCompare(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueIETableCodec constructs the ProtocolIE-Container {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s12.UplinkUEAssociatedLPPaTransportIEContainerValueCodec {
	if !*s00.BridgeUplinkUEAssociatedLPPaTransportIEValueIETableFieldBound(&table) {
		return s12.UplinkUEAssociatedLPPaTransportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UplinkUEAssociatedLPPaTransportIEContainerValueCodec {
		sealed := s12.UplinkUEAssociatedLPPaTransportIEContainerValueCodec{}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UplinkUEAssociatedLPPaTransportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UplinkUEAssociatedLPPaTransportIEField
					if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UplinkUEAssociatedLPPaTransportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEContainer, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PWSRestartIndicationIEs}} codec of TS 36.413.
func PWSRestartIndicationIEValueProtocolErrorIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable) PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSRestartIndicationIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value PWSRestartIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgePWSRestartIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{ResetAcknowledgeIEs}} codec of TS 36.413.
func ResetAcknowledgeIEValueProtocolErrorIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable) ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetAcknowledgeIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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

// S1SetupRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{S1SetupRequestIEs}} codec of TS 36.413.
func S1SetupRequestIEValueProtocolErrorIEContainerListCodec(table s00.S1SetupRequestIEValueIETable) s43.S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s43.S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s43.S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s43.S1SetupRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s43.BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.S1SetupRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s43.S1SetupRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s43.BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s43.S1SetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldEncode(&codec))(s43.S1SetupRequestIEContainer(value), fresh, budget)
		}
		*s43.BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s43.S1SetupRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s43.S1SetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s43.BridgeS1SetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s43.BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s43.S1SetupRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeS1SetupRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeS1SetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNASTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkNASTransport-IEs}} codec of TS 36.413.
func UplinkNASTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable) s32.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s32.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.UplinkNASTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.UplinkNASTransportIEValueProtocolErrorIEContainerList(value), err
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s32.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkNonUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable) s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList(value), err
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkS1cdma2000tunnellingIEs}} codec of TS 36.413.
func UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable) s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList(value), err
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s21.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UplinkUEAssociatedLPPaTransport-IEs}} codec of TS 36.413.
func UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable) s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList(value), err
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PWSRestartIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PWSRestartIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PWSRestartIndicationIEValueProtocolIEContainerListCodec(table s00.PWSRestartIndicationIEValueIETable, bounds aper.ListBounds) PWSRestartIndicationIEValueProtocolIEContainerListValueCodec {
	codec := PWSRestartIndicationIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return PWSRestartIndicationIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return PWSRestartIndicationIEValueProtocolIEContainerList(value), err
	}, encode: func(value PWSRestartIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PWSRestartIndicationIEContainer(value), fresh, budget)
	}, capture: func(v PWSRestartIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v PWSRestartIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// ResetAcknowledgeIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {ResetAcknowledgeIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func ResetAcknowledgeIEValueProtocolIEContainerListCodec(table s00.ResetAcknowledgeIEValueIETable, bounds aper.ListBounds) ResetAcknowledgeIEValueProtocolIEContainerListValueCodec {
	codec := ResetAcknowledgeIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListValueCodec{}
	}
	return ResetAcknowledgeIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetAcknowledgeIEValueProtocolIEContainerList(value), err
	}, encode: func(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetAcknowledgeIEContainer(value), fresh, budget)
	}, capture: func(v ResetAcknowledgeIEValueProtocolIEContainerList, options aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ResetAcknowledgeIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// S1SetupRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {S1SetupRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func S1SetupRequestIEValueProtocolIEContainerListCodec(table s00.S1SetupRequestIEValueIETable, bounds aper.ListBounds) s43.S1SetupRequestIEValueProtocolIEContainerListValueCodec {
	codec := S1SetupRequestIEValueIETableCodec(table, bounds)
	if *s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s43.S1SetupRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s43.S1SetupRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s43.S1SetupRequestIEValueProtocolIEContainerListValueCodec{}
		*s43.BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.S1SetupRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s43.S1SetupRequestIEValueProtocolIEContainerList(value), err
		}
		*s43.BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s43.S1SetupRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s43.BridgeS1SetupRequestIEContainerValueCodecFieldEncode(&codec))(s43.S1SetupRequestIEContainer(value), fresh, budget)
		}
		*s43.BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s43.S1SetupRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s43.S1SetupRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s43.BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s43.BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s43.S1SetupRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeS1SetupRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNASTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkNASTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkNASTransportIEValueProtocolIEContainerListCodec(table s00.UplinkNASTransportIEValueIETable, bounds aper.ListBounds) s32.UplinkNASTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkNASTransportIEValueIETableCodec(table, bounds)
	if *s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.UplinkNASTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s32.UplinkNASTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s32.UplinkNASTransportIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.UplinkNASTransportIEValueProtocolIEContainerList, error) {
			value, err := (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.UplinkNASTransportIEValueProtocolIEContainerList(value), err
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.UplinkNASTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeUplinkNASTransportIEContainerValueCodecFieldEncode(&codec))(s32.UplinkNASTransportIEContainer(value), fresh, budget)
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.UplinkNASTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s32.UplinkNASTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.UplinkNASTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeUplinkNASTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkNonUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.UplinkNonUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkNonUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			value, err := (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList(value), err
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkNonUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkS1cdma2000tunnellingIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListCodec(table s00.UplinkS1cdma2000tunnellingIEValueIETable, bounds aper.ListBounds) s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec {
	codec := UplinkS1cdma2000tunnellingIEValueIETableCodec(table, bounds)
	if *s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec {
		sealed := s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, error) {
			value, err := (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList(value), err
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUplinkS1cdma2000tunnellingIEContainerValueCodecFieldEncode(&codec))(s21.UplinkS1cdma2000tunnellingIEContainer(value), fresh, budget)
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, options aper.DecodeState) (s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUplinkS1cdma2000tunnellingIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UplinkUEAssociatedLPPaTransport-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListCodec(table s00.UplinkUEAssociatedLPPaTransportIEValueIETable, bounds aper.ListBounds) s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
	codec := UplinkUEAssociatedLPPaTransportIEValueIETableCodec(table, bounds)
	if *s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, error) {
			value, err := (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList(value), err
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUplinkUEAssociatedLPPaTransportIEContainerValueCodecFieldEncode(&codec))(s12.UplinkUEAssociatedLPPaTransportIEContainer(value), fresh, budget)
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// pWSRestartIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[PWSRestartIndicationIEValue].
type PWSRestartIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PWSRestartIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PWSRestartIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEField(v *PWSRestartIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePWSRestartIndicationIEValueCompareS1APProtocolIEField(v *PWSRestartIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// resetAcknowledgeIEValueProtocolOpenValue is the concrete protocolOpenValue[ResetAcknowledgeIEValue].
type ResetAcknowledgeIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ResetAcknowledgeIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ResetAcknowledgeIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(v *ResetAcknowledgeIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(v *ResetAcknowledgeIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// s1SetupRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[S1SetupRequestIEValue].
type S1SetupRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s43.S1SetupRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s43.S1SetupRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uplinkNASTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkNASTransportIEValue].
type UplinkNASTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.UplinkNASTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.UplinkNASTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(v *s32.UplinkNASTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeUplinkNASTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeUplinkNASTransportIEFieldFieldReplay(v), *s32.BridgeUplinkNASTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(v *s32.UplinkNASTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeUplinkNASTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeUplinkNASTransportIEFieldFieldReplay(v), *s32.BridgeUplinkNASTransportIEFieldFieldWithoutReplay(v))
}

// uplinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkNonUEAssociatedLPPaTransportIEValue].
type UplinkNonUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.UplinkNonUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.UplinkNonUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s12.UplinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s12.UplinkNonUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeUplinkNonUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}

// uplinkS1cdma2000tunnellingIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkS1cdma2000tunnellingIEValue].
type UplinkS1cdma2000tunnellingIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.UplinkS1cdma2000tunnellingIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.UplinkS1cdma2000tunnellingIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v *s21.UplinkS1cdma2000tunnellingIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s21.BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v), *s21.BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v *s21.UplinkS1cdma2000tunnellingIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s21.BridgeUplinkS1cdma2000tunnellingIEFieldFieldReplay(v), *s21.BridgeUplinkS1cdma2000tunnellingIEFieldFieldWithoutReplay(v))
}

// uplinkUEAssociatedLPPaTransportIEValueProtocolOpenValue is the concrete protocolOpenValue[UplinkUEAssociatedLPPaTransportIEValue].
type UplinkUEAssociatedLPPaTransportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.UplinkUEAssociatedLPPaTransportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.UplinkUEAssociatedLPPaTransportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v *s12.UplinkUEAssociatedLPPaTransportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v *s12.UplinkUEAssociatedLPPaTransportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldReplay(v), *s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldFieldWithoutReplay(v))
}
func BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s21.UserLocationInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s21.BridgeUserLocationInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s21.BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v), *s21.BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionField(v *s21.UserLocationInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeUserLocationInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s21.BridgeUserLocationInformationExtIEsExtFieldFieldReplay(v), *s21.BridgeUserLocationInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// PWSRestartIndicationAPERValue is the concrete APERValue[PWSRestartIndication].
type PWSRestartIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PWSRestartIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationAPERValue) WithoutReplay() PWSRestartIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeAPERValue is the concrete APERValue[ResetAcknowledge].
type ResetAcknowledgeAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResetAcknowledge

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeAPERValue) WithoutReplay() ResetAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1SetupRequestAPERValue is the concrete APERValue[S1SetupRequest].
type S1SetupRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   S1SetupRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1SetupRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1SetupRequestAPERValue) WithoutReplay() S1SetupRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNASTransportAPERValue is the concrete APERValue[UplinkNASTransport].
type UplinkNASTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkNASTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNASTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNASTransportAPERValue) WithoutReplay() UplinkNASTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkNonUEAssociatedLPPaTransportAPERValue is the concrete APERValue[UplinkNonUEAssociatedLPPaTransport].
type UplinkNonUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkNonUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkNonUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkNonUEAssociatedLPPaTransportAPERValue) WithoutReplay() UplinkNonUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkS1cdma2000tunnellingAPERValue is the concrete APERValue[UplinkS1cdma2000tunnelling].
type UplinkS1cdma2000tunnellingAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkS1cdma2000tunnelling

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkS1cdma2000tunnellingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkS1cdma2000tunnellingAPERValue) WithoutReplay() UplinkS1cdma2000tunnellingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UplinkUEAssociatedLPPaTransportAPERValue is the concrete APERValue[UplinkUEAssociatedLPPaTransport].
type UplinkUEAssociatedLPPaTransportAPERValue struct {
	context s00.BridgeCodecContext
	Value   UplinkUEAssociatedLPPaTransport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UplinkUEAssociatedLPPaTransportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UplinkUEAssociatedLPPaTransportAPERValue) WithoutReplay() UplinkUEAssociatedLPPaTransportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABModificationIndicationIEValueERABIEContainerList].
type ERABModificationIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueERABIEContainerList, error)
	encode  func(ERABModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(ERABModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationIEValueERABIEContainerListValueCodec) New(value ERABModificationIndicationIEValueERABIEContainerList) (ERABModificationIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value ERABModificationIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModificationIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ERABModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value ERABModificationIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{E-RABModificationIndicationIEs}} of TS 36.413: a list of information element fields.
type ERABModificationIndicationIEValueERABIEContainerList []ERABModificationIndicationIEValueProtocolIESingleContainer

// PWSRestartIndicationIEValueERABIEContainerListValueCodec is the concrete ValueCodec[PWSRestartIndicationIEValueERABIEContainerList].
type PWSRestartIndicationIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, error)
	encode  func(PWSRestartIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndicationIEValueERABIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot)
	compare func(PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationIEValueERABIEContainerListValueCodec) New(value PWSRestartIndicationIEValueERABIEContainerList) (PWSRestartIndicationIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationIEValueERABIEContainerListValueCodec) EncodeAPER(value PWSRestartIndicationIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PWSRestartIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationIEValueERABIEContainerListValueCodec) encodeChanged(value PWSRestartIndicationIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSRestartIndicationIEValueERABIEContainerList is E-RAB-IE-ContainerList {{PWSRestartIndicationIEs}} of TS 36.413: a list of information element fields.
type PWSRestartIndicationIEValueERABIEContainerList []PWSRestartIndicationIEValueProtocolIESingleContainer

func BridgePWSRestartIndicationIEValueCaptureS1APERABIEContainerList(v *PWSRestartIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSRestartIndicationIEValueCompareS1APERABIEContainerList(v *PWSRestartIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetAcknowledgeIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueERABIEContainerList].
type ResetAcknowledgeIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) New(value ResetAcknowledgeIEValueERABIEContainerList) (ResetAcknowledgeIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueERABIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ResetAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ResetAcknowledgeIEValueERABIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APERABIEContainerList(v *ResetAcknowledgeIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APERABIEContainerList(v *ResetAcknowledgeIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeS1SetupRequestIEValueCompareS1APERABIEContainerList(v *s43.S1SetupRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APERABIEContainerList(v *s32.UplinkNASTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APERABIEContainerList(v *s32.UplinkNASTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APERABIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APERABIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APERABIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APERABIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationIEFieldValueCodec is the concrete ValueCodec[ERABModificationIndicationIEField].
type ERABModificationIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndicationIEField, error)
	encode  func(ERABModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndicationIEField, aper.DecodeState) (ERABModificationIndicationIEField, aper.Snapshot)
	compare func(ERABModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationIEFieldValueCodec) New(value ERABModificationIndicationIEField) (ERABModificationIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationIEFieldValueCodec) EncodeAPER(value ERABModificationIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModificationIndicationIEFieldValueCodec) encodeBudgetValue(value ERABModificationIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationIEFieldValueCodec) encodeChanged(value ERABModificationIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSRestartIndicationIEFieldValueCodec is the concrete ValueCodec[PWSRestartIndicationIEField].
type PWSRestartIndicationIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndicationIEField, error)
	encode  func(PWSRestartIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndicationIEField, aper.DecodeState) (PWSRestartIndicationIEField, aper.Snapshot)
	compare func(PWSRestartIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationIEFieldValueCodec) New(value PWSRestartIndicationIEField) (PWSRestartIndicationIEFieldAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationIEFieldValueCodec) EncodeAPER(value PWSRestartIndicationIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationIEFieldValueCodec) encodeBudgetValue(value PWSRestartIndicationIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationIEFieldValueCodec) encodeChanged(value PWSRestartIndicationIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEFieldValueCodec is the concrete ValueCodec[ResetAcknowledgeIEField].
type ResetAcknowledgeIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEField, error)
	encode  func(ResetAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEField, aper.DecodeState) (ResetAcknowledgeIEField, aper.Snapshot)
	compare func(ResetAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEFieldValueCodec) New(value ResetAcknowledgeIEField) (ResetAcknowledgeIEFieldAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEFieldValueCodec) EncodeAPER(value ResetAcknowledgeIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEFieldValueCodec) encodeBudgetValue(value ResetAcknowledgeIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEFieldValueCodec) encodeChanged(value ResetAcknowledgeIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationIndicationIEContainerValueCodec is the concrete ValueCodec[ERABModificationIndicationIEContainer].
type ERABModificationIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndicationIEContainer, error)
	encode  func(ERABModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndicationIEContainer, aper.DecodeState) (ERABModificationIndicationIEContainer, aper.Snapshot)
	compare func(ERABModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationIEContainerValueCodec) New(value ERABModificationIndicationIEContainer) (ERABModificationIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationIEContainerValueCodec) EncodeAPER(value ERABModificationIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModificationIndicationIEContainerValueCodec) encodeBudgetValue(value ERABModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationIEContainerValueCodec) encodeChanged(value ERABModificationIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSRestartIndicationIEContainerValueCodec is the concrete ValueCodec[PWSRestartIndicationIEContainer].
type PWSRestartIndicationIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndicationIEContainer, error)
	encode  func(PWSRestartIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndicationIEContainer, aper.DecodeState) (PWSRestartIndicationIEContainer, aper.Snapshot)
	compare func(PWSRestartIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationIEContainerValueCodec) New(value PWSRestartIndicationIEContainer) (PWSRestartIndicationIEContainerAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationIEContainerValueCodec) EncodeAPER(value PWSRestartIndicationIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationIEContainerValueCodec) encodeBudgetValue(value PWSRestartIndicationIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationIEContainerValueCodec) encodeChanged(value PWSRestartIndicationIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEContainerValueCodec is the concrete ValueCodec[ResetAcknowledgeIEContainer].
type ResetAcknowledgeIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEContainer, error)
	encode  func(ResetAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEContainer, aper.DecodeState) (ResetAcknowledgeIEContainer, aper.Snapshot)
	compare func(ResetAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEContainerValueCodec) New(value ResetAcknowledgeIEContainer) (ResetAcknowledgeIEContainerAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEContainerValueCodec) EncodeAPER(value ResetAcknowledgeIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEContainerValueCodec) encodeBudgetValue(value ResetAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEContainerValueCodec) encodeChanged(value ResetAcknowledgeIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ERABModificationIndicationIEValueProtocolErrorIEContainerList].
type ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value ERABModificationIndicationIEValueProtocolErrorIEContainerList) (ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ERABModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ERABModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{E-RABModificationIndicationIEs}} of TS 36.413: a list of information element fields.
type ERABModificationIndicationIEValueProtocolErrorIEContainerList []ERABModificationIndicationIEValueProtocolIESingleContainer

// PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[PWSRestartIndicationIEValueProtocolErrorIEContainerList].
type PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, error)
	encode  func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) New(value PWSRestartIndicationIEValueProtocolErrorIEContainerList) (PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PWSRestartIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PWSRestartIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSRestartIndicationIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{PWSRestartIndicationIEs}} of TS 36.413: a list of information element fields.
type PWSRestartIndicationIEValueProtocolErrorIEContainerList []PWSRestartIndicationIEValueProtocolIESingleContainer

func BridgePWSRestartIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *PWSRestartIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSRestartIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *PWSRestartIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueProtocolErrorIEContainerList].
type ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) New(value ResetAcknowledgeIEValueProtocolErrorIEContainerList) (ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ResetAcknowledgeIEs}} of TS 36.413: a list of information element fields.
type ResetAcknowledgeIEValueProtocolErrorIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolErrorIEContainerList(v *ResetAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolErrorIEContainerList(v *ResetAcknowledgeIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s43.S1SetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s32.UplinkNASTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolErrorIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolErrorIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ERABModificationIndicationIEValueProtocolIEContainerList].
type ERABModificationIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueProtocolIEContainerList, error)
	encode  func(ERABModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ERABModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ERABModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) New(value ERABModificationIndicationIEValueProtocolIEContainerList) (ERABModificationIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ERABModificationIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ERABModificationIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ERABModificationIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ERABModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value ERABModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ERABModificationIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {E-RABModificationIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ERABModificationIndicationIEValueProtocolIEContainerList []ERABModificationIndicationIEValueProtocolIESingleContainer

// PWSRestartIndicationIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[PWSRestartIndicationIEValueProtocolIEContainerList].
type PWSRestartIndicationIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, error)
	encode  func(PWSRestartIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PWSRestartIndicationIEValueProtocolIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) New(value PWSRestartIndicationIEValueProtocolIEContainerList) (PWSRestartIndicationIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PWSRestartIndicationIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PWSRestartIndicationIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PWSRestartIndicationIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PWSRestartIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) encodeChanged(value PWSRestartIndicationIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PWSRestartIndicationIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {PWSRestartIndicationIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type PWSRestartIndicationIEValueProtocolIEContainerList []PWSRestartIndicationIEValueProtocolIESingleContainer

func BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainerList(v *PWSRestartIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainerList(v *PWSRestartIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgePWSRestartIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetAcknowledgeIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ResetAcknowledgeIEValueProtocolIEContainerList].
type ResetAcknowledgeIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, error)
	encode  func(ResetAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) New(value ResetAcknowledgeIEValueProtocolIEContainerList) (ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAcknowledgeIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ResetAcknowledgeIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) encodeChanged(value ResetAcknowledgeIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAcknowledgeIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ResetAcknowledgeIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ResetAcknowledgeIEValueProtocolIEContainerList []ResetAcknowledgeIEValueProtocolIESingleContainer

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainerList(v *ResetAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainerList(v *ResetAcknowledgeIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainerList(v *s43.S1SetupRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeS1SetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainerList(v *s32.UplinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainerList(v *s32.UplinkNASTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainerList(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainerList(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABModificationIndicationIEValueERABIEContainerList].
type ERABModificationIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() ERABModificationIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{E-RABModificationIndicationIEs}} of TS 36.413: a single information element field.
type ERABModificationIndicationIEValueProtocolIESingleContainer = ERABModificationIndicationIEField

// PWSRestartIndicationIEValueERABIEContainerListAPERValue is the concrete APERValue[PWSRestartIndicationIEValueERABIEContainerList].
type PWSRestartIndicationIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSRestartIndicationIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEValueERABIEContainerListAPERValue) WithoutReplay() PWSRestartIndicationIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSRestartIndicationIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{PWSRestartIndicationIEs}} of TS 36.413: a single information element field.
type PWSRestartIndicationIEValueProtocolIESingleContainer = PWSRestartIndicationIEField

func BridgePWSRestartIndicationIEValueCaptureS1APProtocolIESingleContainer(v *PWSRestartIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePWSRestartIndicationIEValueCompareS1APProtocolIESingleContainer(v *PWSRestartIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSRestartIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ResetAcknowledgeIEValueERABIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueERABIEContainerList].
type ResetAcknowledgeIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueERABIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ResetAcknowledgeIEs}} of TS 36.413: a single information element field.
type ResetAcknowledgeIEValueProtocolIESingleContainer = ResetAcknowledgeIEField

func BridgeResetAcknowledgeIEValueCaptureS1APProtocolIESingleContainer(v *ResetAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeResetAcknowledgeIEValueCompareS1APProtocolIESingleContainer(v *ResetAcknowledgeIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeS1SetupRequestIEValueCompareS1APProtocolIESingleContainer(v *s43.S1SetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s43.BridgeS1SetupRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNASTransportIEValueCaptureS1APProtocolIESingleContainer(v *s32.UplinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkNASTransportIEValueCompareS1APProtocolIESingleContainer(v *s32.UplinkNASTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s12.UplinkNonUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIESingleContainer(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIESingleContainer(v *s21.UplinkS1cdma2000tunnellingIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIESingleContainer(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIESingleContainer(v *s12.UplinkUEAssociatedLPPaTransportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ERABModificationIndicationIEFieldAPERValue is the concrete APERValue[ERABModificationIndicationIEField].
type ERABModificationIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEFieldAPERValue) WithoutReplay() ERABModificationIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSRestartIndicationIEFieldAPERValue is the concrete APERValue[PWSRestartIndicationIEField].
type PWSRestartIndicationIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSRestartIndicationIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEFieldAPERValue) WithoutReplay() PWSRestartIndicationIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEFieldAPERValue is the concrete APERValue[ResetAcknowledgeIEField].
type ResetAcknowledgeIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEFieldAPERValue) WithoutReplay() ResetAcknowledgeIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationIndicationIEContainerAPERValue is the concrete APERValue[ERABModificationIndicationIEContainer].
type ERABModificationIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEContainerAPERValue) WithoutReplay() ERABModificationIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSRestartIndicationIEContainerAPERValue is the concrete APERValue[PWSRestartIndicationIEContainer].
type PWSRestartIndicationIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSRestartIndicationIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEContainerAPERValue) WithoutReplay() PWSRestartIndicationIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEContainerAPERValue is the concrete APERValue[ResetAcknowledgeIEContainer].
type ResetAcknowledgeIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEContainerAPERValue) WithoutReplay() ResetAcknowledgeIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ERABModificationIndicationIEValueProtocolErrorIEContainerList].
type ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[PWSRestartIndicationIEValueProtocolErrorIEContainerList].
type PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSRestartIndicationIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueProtocolErrorIEContainerList].
type ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ERABModificationIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ERABModificationIndicationIEValueProtocolIEContainerList].
type ERABModificationIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ERABModificationIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() ERABModificationIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PWSRestartIndicationIEValueProtocolIEContainerListAPERValue is the concrete APERValue[PWSRestartIndicationIEValueProtocolIEContainerList].
type PWSRestartIndicationIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PWSRestartIndicationIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) WithoutReplay() PWSRestartIndicationIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAcknowledgeIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ResetAcknowledgeIEValueProtocolIEContainerList].
type ResetAcknowledgeIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetAcknowledgeIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) WithoutReplay() ResetAcknowledgeIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APERABModificationIndicationIEValue(v *ERABModificationIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(199):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedListBearerModInd == nil)
				if v.rowERABToBeModifiedListBearerModInd != nil {
					s25.BridgeCaptureS1APERABToBeModifiedListBearerModInd(v.rowERABToBeModifiedListBearerModInd, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(201):
			{
				f := s.Begin()
				s.Bool(v.rowERABNotToBeModifiedListBearerModInd == nil)
				if v.rowERABNotToBeModifiedListBearerModInd != nil {
					s24.BridgeCaptureS1APERABNotToBeModifiedListBearerModInd(v.rowERABNotToBeModifiedListBearerModInd, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s14.BridgeCaptureS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s35.BridgeCaptureS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					BridgeCaptureS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModificationIndicationIEValue) captureSemantics(s aper.SemanticCapture) ERABModificationIndicationIEValue {
	BridgeCaptureS1APERABModificationIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APERABModificationIndicationIEValue(v *ERABModificationIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(199):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeModifiedListBearerModInd == nil)
				if v.rowERABToBeModifiedListBearerModInd != nil {
					s25.BridgeCompareS1APERABToBeModifiedListBearerModInd(v.rowERABToBeModifiedListBearerModInd, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(201):
			{
				f := s.Begin()
				s.Bool(v.rowERABNotToBeModifiedListBearerModInd == nil)
				if v.rowERABNotToBeModifiedListBearerModInd != nil {
					s24.BridgeCompareS1APERABNotToBeModifiedListBearerModInd(v.rowERABNotToBeModifiedListBearerModInd, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(226):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipInfo == nil)
				if v.rowCSGMembershipInfo != nil {
					s14.BridgeCompareS1APCSGMembershipInfo(v.rowCSGMembershipInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(176):
			{
				f := s.Begin()
				s.Bool(v.rowTunnelInformationForBBF == nil)
				if v.rowTunnelInformationForBBF != nil {
					s35.BridgeCompareS1APTunnelInformation(v.rowTunnelInformationForBBF, s)
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
		case s00.ProtocolIEID(189):
			{
				f := s.Begin()
				s.Bool(v.rowUserLocationInformation == nil)
				if v.rowUserLocationInformation != nil {
					BridgeCompareS1APUserLocationInformation(v.rowUserLocationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ERABModificationIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APERABModificationIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APPWSRestartIndication(v *PWSRestartIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSRestartIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPWSRestartIndication(v *PWSRestartIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePWSRestartIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPWSRestartIndicationIEValue(v *PWSRestartIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(182):
			{
				f := s.Begin()
				s.Bool(v.rowECGIListForRestart == nil)
				if v.rowECGIListForRestart != nil {
					s21.BridgeCaptureS1APECGIListForRestart(v.rowECGIListForRestart, s)
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
		case s00.ProtocolIEID(188):
			{
				f := s.Begin()
				s.Bool(v.rowTAIListForRestart == nil)
				if v.rowTAIListForRestart != nil {
					s32.BridgeCaptureS1APTAIListForRestart(v.rowTAIListForRestart, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(190):
			{
				f := s.Begin()
				s.Bool(v.rowEmergencyAreaIDListForRestart == nil)
				if v.rowEmergencyAreaIDListForRestart != nil {
					s00.BridgeCaptureS1APEmergencyAreaIDListForRestart(v.rowEmergencyAreaIDListForRestart, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PWSRestartIndicationIEValue) captureSemantics(s aper.SemanticCapture) PWSRestartIndicationIEValue {
	BridgeCaptureS1APPWSRestartIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPWSRestartIndicationIEValue(v *PWSRestartIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(182):
			{
				f := s.Begin()
				s.Bool(v.rowECGIListForRestart == nil)
				if v.rowECGIListForRestart != nil {
					s24.BridgeCompareS1APECGIListForRestart(v.rowECGIListForRestart, s)
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
		case s00.ProtocolIEID(188):
			{
				f := s.Begin()
				s.Bool(v.rowTAIListForRestart == nil)
				if v.rowTAIListForRestart != nil {
					s32.BridgeCompareS1APTAIListForRestart(v.rowTAIListForRestart, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(190):
			{
				f := s.Begin()
				s.Bool(v.rowEmergencyAreaIDListForRestart == nil)
				if v.rowEmergencyAreaIDListForRestart != nil {
					s02.BridgeCompareS1APEmergencyAreaIDListForRestart(v.rowEmergencyAreaIDListForRestart, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PWSRestartIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPWSRestartIndicationIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APResetAcknowledge(v *ResetAcknowledge, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APResetAcknowledge(v *ResetAcknowledge, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetAcknowledgeIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APResetAcknowledgeIEValue(v *ResetAcknowledgeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(93):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionListResAck == nil)
				if v.rowUEAssociatedLogicalS1ConnectionListResAck != nil {
					s36.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(v.rowUEAssociatedLogicalS1ConnectionListResAck, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCaptureS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetAcknowledgeIEValue) captureSemantics(s aper.SemanticCapture) ResetAcknowledgeIEValue {
	BridgeCaptureS1APResetAcknowledgeIEValue(&v, &s)
	return v
}
func BridgeCompareS1APResetAcknowledgeIEValue(v *ResetAcknowledgeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(93):
			{
				f := s.Begin()
				s.Bool(v.rowUEAssociatedLogicalS1ConnectionListResAck == nil)
				if v.rowUEAssociatedLogicalS1ConnectionListResAck != nil {
					s36.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(v.rowUEAssociatedLogicalS1ConnectionListResAck, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(58):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s22.BridgeCompareS1APCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetAcknowledgeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APResetAcknowledgeIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APS1SetupRequest(v *S1SetupRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s43.BridgeS1SetupRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APS1SetupRequest(v *S1SetupRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s43.BridgeS1SetupRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTACListInLTENTNComplete(v *TACListInLTENTNComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTACListInLTENTN(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTACListInLTENTNComplete(v *TACListInLTENTNComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTACListInLTENTN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIBroadcastComplete(v *TAIBroadcastComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIBroadcast(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIBroadcastComplete(v *TAIBroadcastComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAIBroadcast(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAICancelledComplete(v *TAICancelledComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAICancelled(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAICancelledComplete(v *TAICancelledComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAICancelled(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListComplete(v *TAIListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s33.BridgeCaptureS1APTAIList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListComplete(v *TAIListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s33.BridgeCompareS1APTAIList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListForRestartComplete(v *TAIListForRestartComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListForRestart(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListForRestartComplete(v *TAIListForRestartComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAIListForRestart(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforMDTComplete(v *TAIListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforMDTComplete(v *TAIListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAIListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforQMCComplete(v *TAIListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforQMCComplete(v *TAIListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAIListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIListforWarningComplete(v *TAIListforWarningComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APTAIListforWarning(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAIListforWarningComplete(v *TAIListforWarningComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APTAIListforWarning(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAListforMDTComplete(v *TAListforMDTComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforMDT(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAListforMDTComplete(v *TAListforMDTComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAListforMDT(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAListforQMCComplete(v *TAListforQMCComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APTAListforQMC(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTAListforQMCComplete(v *TAListforQMCComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APTAListforQMC(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v *UEAssociatedLogicalS1ConnectionListResAckComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v *UEAssociatedLogicalS1ConnectionListResAckComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResComplete(v *UEAssociatedLogicalS1ConnectionListResComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v *UEAssociatedLogicalS1ConnectionListResComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s36.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEHistoryInformationComplete(v *UEHistoryInformationComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCaptureS1APUEHistoryInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEHistoryInformationComplete(v *UEHistoryInformationComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s41.BridgeCompareS1APUEHistoryInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkNASTransport(v *UplinkNASTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkNASTransport(v *UplinkNASTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNASTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(v *UplinkNonUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v *UplinkNonUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkNonUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkS1cdma2000tunnelling(v *UplinkS1cdma2000tunnelling, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkS1cdma2000tunnelling(v *UplinkS1cdma2000tunnelling, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkS1cdma2000tunnellingIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(v *UplinkUEAssociatedLPPaTransport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v *UplinkUEAssociatedLPPaTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUplinkUEAssociatedLPPaTransportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUserLocationInformation(v *UserLocationInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCaptureS1APEUTRANCGI(&v.EutranCgi, s)
	s31.BridgeCaptureS1APTAI(&v.Tai, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUserLocationInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUserLocationInformation(v *UserLocationInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s17.BridgeCompareS1APEUTRANCGI(&v.EutranCgi, s)
	s31.BridgeCompareS1APTAI(&v.Tai, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUserLocationInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

// UserLocationInformation represents the ASN.1 type UserLocationInformation (SEQUENCE).
type UserLocationInformation struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	EutranCgi         s17.EUTRANCGI                                 `asn1:"tag:0,context,implicit"`
	Tai               s31.TAI                                       `asn1:"tag:1,context,implicit"`
	IEExtensions      s21.UserLocationInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                          `asn1:"-" json:"-"`
	extCount          int64                                         `asn1:"-" json:"-"`
	extPresent        []bool                                        `asn1:"-" json:"-"`
	extData           [][]byte                                      `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// UnmarshalAPERSupportedTAs decodes a SupportedTAs list from APER.
func BridgeUnmarshalAPERSupportedTAs(data []byte) (s43.SupportedTAsComplete, error) {
	var value s43.SupportedTAsComplete
	if err := s43.BridgeSupportedTAsCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// TACListInLTENTNComplete carries a complete TACListInLTENTN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TACListInLTENTNComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.TACListInLTENTN
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TACListInLTENTNComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERTACListInLTENTNTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TACListInLTENTN from APER format.
func (v *TACListInLTENTNComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TACListInLTENTN with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TACListInLTENTNComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TACListInLTENTN")
	}
	bb.EnterComponent("TACListInLTENTN")
	value, err := BridgeUnmarshalAPERTACListInLTENTNFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TACListInLTENTN")
	}
	padding, err := aper.CaptureFinalBits(bb, "TACListInLTENTN")
	if err != nil {
		return runtime.WrapDecodePath(err, "TACListInLTENTN")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTACListInLTENTN encodes a TACListInLTENTN list to APER.
func BridgeMarshalAPERTACListInLTENTN(list TACListInLTENTNComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTACListInLTENTN decodes a TACListInLTENTN list from APER.
func BridgeUnmarshalAPERTACListInLTENTN(data []byte) (TACListInLTENTNComplete, error) {
	var value TACListInLTENTNComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTACListInLTENTNFrom decodes a TACListInLTENTN list from bb.
func BridgeUnmarshalAPERTACListInLTENTNFrom(bb *aper.BitBuffer) (s00.TACListInLTENTN, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERTACListInLTENTNListValue
	if err := BridgeUnmarshalAPERTACListInLTENTNInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTACListInLTENTNInto(v *s00.BridgeAsn1cAPERTACListInLTENTNListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.TACListInLTENTN, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 12, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
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

// TAIListforMDTComplete carries a complete TAIListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAIListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforMDT from APER format.
func (v *TAIListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIListforMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	bb.EnterComponent("TAIListforMDT")
	value, err := BridgeUnmarshalAPERTAIListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforMDT encodes a TAIListforMDT list to APER.
func BridgeMarshalAPERTAIListforMDT(list TAIListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforMDT decodes a TAIListforMDT list from APER.
func BridgeUnmarshalAPERTAIListforMDT(data []byte) (TAIListforMDTComplete, error) {
	var value TAIListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforMDTFrom decodes a TAIListforMDT list from bb.
func BridgeUnmarshalAPERTAIListforMDTFrom(bb *aper.BitBuffer) (s32.TAIListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAIListforMDTListValue
	if err := BridgeUnmarshalAPERTAIListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforMDTInto(v *s32.BridgeAsn1cAPERTAIListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAIListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s31.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAIListforWarningComplete carries a complete TAIListforWarning encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforWarningComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAIListforWarning
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforWarningComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIListforWarningTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforWarning from APER format.
func (v *TAIListforWarningComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIListforWarning with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIListforWarningComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	bb.EnterComponent("TAIListforWarning")
	value, err := BridgeUnmarshalAPERTAIListforWarningFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforWarning")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforWarning")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforWarning encodes a TAIListforWarning list to APER.
func BridgeMarshalAPERTAIListforWarning(list TAIListforWarningComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforWarning decodes a TAIListforWarning list from APER.
func BridgeUnmarshalAPERTAIListforWarning(data []byte) (TAIListforWarningComplete, error) {
	var value TAIListforWarningComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforWarningFrom decodes a TAIListforWarning list from bb.
func BridgeUnmarshalAPERTAIListforWarningFrom(bb *aper.BitBuffer) (s32.TAIListforWarning, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAIListforWarningListValue
	if err := BridgeUnmarshalAPERTAIListforWarningInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforWarningInto(v *s32.BridgeAsn1cAPERTAIListforWarningListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAIListforWarning, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s31.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAIBroadcastComplete carries a complete TAIBroadcast encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIBroadcastComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAIBroadcast
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIBroadcastComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIBroadcastTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIBroadcast from APER format.
func (v *TAIBroadcastComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIBroadcast with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIBroadcastComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcast")
	}
	bb.EnterComponent("TAIBroadcast")
	value, err := BridgeUnmarshalAPERTAIBroadcastFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcast")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIBroadcast")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIBroadcast")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIBroadcast encodes a TAIBroadcast list to APER.
func BridgeMarshalAPERTAIBroadcast(list TAIBroadcastComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIBroadcast decodes a TAIBroadcast list from APER.
func BridgeUnmarshalAPERTAIBroadcast(data []byte) (TAIBroadcastComplete, error) {
	var value TAIBroadcastComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIBroadcastFrom decodes a TAIBroadcast list from bb.
func BridgeUnmarshalAPERTAIBroadcastFrom(bb *aper.BitBuffer) (s32.TAIBroadcast, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAIBroadcastListValue
	if err := BridgeUnmarshalAPERTAIBroadcastInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIBroadcastInto(v *s32.BridgeAsn1cAPERTAIBroadcastListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAIBroadcast, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s32.TAIBroadcastItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s32.BridgeTAIBroadcastItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAICancelledComplete carries a complete TAICancelled encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAICancelledComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAICancelled
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAICancelledComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAICancelledTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAICancelled from APER format.
func (v *TAICancelledComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAICancelled with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAICancelledComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAICancelled")
	}
	bb.EnterComponent("TAICancelled")
	value, err := BridgeUnmarshalAPERTAICancelledFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAICancelled")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAICancelled")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAICancelled")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAICancelled encodes a TAICancelled list to APER.
func BridgeMarshalAPERTAICancelled(list TAICancelledComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAICancelled decodes a TAICancelled list from APER.
func BridgeUnmarshalAPERTAICancelled(data []byte) (TAICancelledComplete, error) {
	var value TAICancelledComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAICancelledFrom decodes a TAICancelled list from bb.
func BridgeUnmarshalAPERTAICancelledFrom(bb *aper.BitBuffer) (s32.TAICancelled, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAICancelledListValue
	if err := BridgeUnmarshalAPERTAICancelledInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAICancelledInto(v *s32.BridgeAsn1cAPERTAICancelledListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAICancelled, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s32.TAICancelledItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s32.BridgeTAICancelledItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAListforMDTComplete carries a complete TAListforMDT encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAListforMDTComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.TAListforMDT
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAListforMDTComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERTAListforMDTTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAListforMDT from APER format.
func (v *TAListforMDTComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAListforMDT with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAListforMDTComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	bb.EnterComponent("TAListforMDT")
	value, err := BridgeUnmarshalAPERTAListforMDTFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAListforMDT")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforMDT")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAListforMDT encodes a TAListforMDT list to APER.
func BridgeMarshalAPERTAListforMDT(list TAListforMDTComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAListforMDT decodes a TAListforMDT list from APER.
func BridgeUnmarshalAPERTAListforMDT(data []byte) (TAListforMDTComplete, error) {
	var value TAListforMDTComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAListforMDTFrom decodes a TAListforMDT list from bb.
func BridgeUnmarshalAPERTAListforMDTFrom(bb *aper.BitBuffer) (s00.TAListforMDT, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERTAListforMDTListValue
	if err := BridgeUnmarshalAPERTAListforMDTInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAListforMDTInto(v *s00.BridgeAsn1cAPERTAListforMDTListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.TAListforMDT, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
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

// TAListforQMCComplete carries a complete TAListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.TAListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERTAListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAListforQMC from APER format.
func (v *TAListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAListforQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	bb.EnterComponent("TAListforQMC")
	value, err := BridgeUnmarshalAPERTAListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAListforQMC encodes a TAListforQMC list to APER.
func BridgeMarshalAPERTAListforQMC(list TAListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAListforQMC decodes a TAListforQMC list from APER.
func BridgeUnmarshalAPERTAListforQMC(data []byte) (TAListforQMCComplete, error) {
	var value TAListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAListforQMCFrom decodes a TAListforQMC list from bb.
func BridgeUnmarshalAPERTAListforQMCFrom(bb *aper.BitBuffer) (s00.TAListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERTAListforQMCListValue
	if err := BridgeUnmarshalAPERTAListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAListforQMCInto(v *s00.BridgeAsn1cAPERTAListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.TAListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
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

// TAIListforQMCComplete carries a complete TAIListforQMC encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListforQMCComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAIListforQMC
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListforQMCComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIListforQMCTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListforQMC from APER format.
func (v *TAIListforQMCComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIListforQMC with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIListforQMCComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	bb.EnterComponent("TAIListforQMC")
	value, err := BridgeUnmarshalAPERTAIListforQMCFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListforQMC")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListforQMC")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListforQMC encodes a TAIListforQMC list to APER.
func BridgeMarshalAPERTAIListforQMC(list TAIListforQMCComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListforQMC decodes a TAIListforQMC list from APER.
func BridgeUnmarshalAPERTAIListforQMC(data []byte) (TAIListforQMCComplete, error) {
	var value TAIListforQMCComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListforQMCFrom decodes a TAIListforQMC list from bb.
func BridgeUnmarshalAPERTAIListforQMCFrom(bb *aper.BitBuffer) (s32.TAIListforQMC, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAIListforQMCListValue
	if err := BridgeUnmarshalAPERTAIListforQMCInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListforQMCInto(v *s32.BridgeAsn1cAPERTAIListforQMCListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAIListforQMC, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s31.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// TAIListForRestartComplete carries a complete TAIListForRestart encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListForRestartComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s32.TAIListForRestart
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListForRestartComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIListForRestartTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIListForRestart from APER format.
func (v *TAIListForRestartComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIListForRestart with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIListForRestartComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIListForRestart")
	}
	bb.EnterComponent("TAIListForRestart")
	value, err := BridgeUnmarshalAPERTAIListForRestartFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListForRestart")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIListForRestart")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIListForRestart")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIListForRestart encodes a TAIListForRestart list to APER.
func BridgeMarshalAPERTAIListForRestart(list TAIListForRestartComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERTAIListForRestart decodes a TAIListForRestart list from APER.
func BridgeUnmarshalAPERTAIListForRestart(data []byte) (TAIListForRestartComplete, error) {
	var value TAIListForRestartComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListForRestartFrom decodes a TAIListForRestart list from bb.
func BridgeUnmarshalAPERTAIListForRestartFrom(bb *aper.BitBuffer) (s32.TAIListForRestart, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s32.BridgeAsn1cAPERTAIListForRestartListValue
	if err := BridgeUnmarshalAPERTAIListForRestartInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListForRestartInto(v *s32.BridgeAsn1cAPERTAIListForRestartListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s32.TAIListForRestart, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s31.TAI
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UEHistoryInformationComplete carries a complete UEHistoryInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEHistoryInformationComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s41.UEHistoryInformation
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEHistoryInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s42.BridgeMarshalAPERUEHistoryInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEHistoryInformation from APER format.
func (v *UEHistoryInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEHistoryInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEHistoryInformationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	bb.EnterComponent("UEHistoryInformation")
	value, err := BridgeUnmarshalAPERUEHistoryInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEHistoryInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEHistoryInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEHistoryInformation encodes a UEHistoryInformation list to APER.
func BridgeMarshalAPERUEHistoryInformation(list UEHistoryInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEHistoryInformation decodes a UEHistoryInformation list from APER.
func BridgeUnmarshalAPERUEHistoryInformation(data []byte) (UEHistoryInformationComplete, error) {
	var value UEHistoryInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEHistoryInformationFrom decodes a UEHistoryInformation list from bb.
func BridgeUnmarshalAPERUEHistoryInformationFrom(bb *aper.BitBuffer) (s41.UEHistoryInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s41.BridgeAsn1cAPERUEHistoryInformationListValue
	if err := BridgeUnmarshalAPERUEHistoryInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEHistoryInformationInto(v *s41.BridgeAsn1cAPERUEHistoryInformationListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s41.UEHistoryInformation, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s41.LastVisitedCellItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s41.BridgeLastVisitedCellItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UserLocationInformation to APER format.
func (v *UserLocationInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UserLocationInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s17.BridgeEUTRANCGIMethodMarshalAPERTo(&v.EutranCgi, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding eutran-cgi: %w", err)
	}
	if err := s31.BridgeTAIMethodMarshalAPERTo(&v.Tai, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding tai: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UserLocationInformation from APER format.
func (v *UserLocationInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UserLocationInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UserLocationInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	bb.EnterComponent("UserLocationInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "UserLocationInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "UserLocationInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UserLocationInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UserLocationInformation{}
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
	toleranceMark_eutrancgi := bb.EnterComponent("EutranCgi")
	if err := s17.BridgeEUTRANCGIMethodUnmarshalAPERFrom(&v.EutranCgi, bb); err != nil {
		return runtime.WrapDecodePath(err, "EutranCgi")
	}
	bb.LeaveComponent(toleranceMark_eutrancgi)
	toleranceMark_tai := bb.EnterComponent("Tai")
	if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&v.Tai, bb); err != nil {
		return runtime.WrapDecodePath(err, "Tai")
	}
	bb.LeaveComponent(toleranceMark_tai)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s21.UserLocationInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s21.UserLocationInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s21.BridgeUserLocationInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// WLANMeasConfigNameListComplete carries a complete WLANMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s00.WLANMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *WLANMeasConfigNameListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERWLANMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasConfigNameList from APER format.
func (v *WLANMeasConfigNameListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasConfigNameList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasConfigNameListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	bb.EnterComponent("WLANMeasConfigNameList")
	value, err := BridgeUnmarshalAPERWLANMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasConfigNameList encodes a WLANMeasConfigNameList list to APER.
func BridgeMarshalAPERWLANMeasConfigNameList(list WLANMeasConfigNameListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERWLANMeasConfigNameList decodes a WLANMeasConfigNameList list from APER.
func BridgeUnmarshalAPERWLANMeasConfigNameList(data []byte) (WLANMeasConfigNameListComplete, error) {
	var value WLANMeasConfigNameListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANMeasConfigNameListFrom decodes a WLANMeasConfigNameList list from bb.
func BridgeUnmarshalAPERWLANMeasConfigNameListFrom(bb *aper.BitBuffer) (s00.WLANMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERWLANMeasConfigNameListListValue
	if err := BridgeUnmarshalAPERWLANMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANMeasConfigNameListInto(v *s00.BridgeAsn1cAPERWLANMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.WLANMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1191
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TACListInLTENTNComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TACListInLTENTNComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TACListInLTENTNComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TACListInLTENTNComplete) WithoutReplay() TACListInLTENTNComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TACListInLTENTNComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIBroadcastComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIBroadcastComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIBroadcastComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIBroadcastComplete) WithoutReplay() TAIBroadcastComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIBroadcastComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAICancelledComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAICancelledComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAICancelledComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAICancelledComplete) WithoutReplay() TAICancelledComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAICancelledComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListForRestartComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListForRestartComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListForRestartComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListForRestartComplete) WithoutReplay() TAIListForRestartComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListForRestartComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforMDTComplete) WithoutReplay() TAIListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforQMCComplete) WithoutReplay() TAIListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListforWarningComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListforWarningComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListforWarningComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListforWarningComplete) WithoutReplay() TAIListforWarningComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListforWarningComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAListforMDTComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAListforMDTComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAListforMDTComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAListforMDTComplete) WithoutReplay() TAListforMDTComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAListforMDTComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAListforQMCComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAListforQMCComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAListforQMCComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAListforQMCComplete) WithoutReplay() TAListforQMCComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAListforQMCComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEHistoryInformationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEHistoryInformationComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEHistoryInformationComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEHistoryInformationComplete) WithoutReplay() UEHistoryInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEHistoryInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UserLocationInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UserLocationInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UserLocationInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UserLocationInformation) WithoutReplay() UserLocationInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UserLocationInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasConfigNameListComplete) WithoutReplay() WLANMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WLANMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UserLocationInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UserLocationInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UserLocationInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UserLocationInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TACListInLTENTNComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TACListInLTENTNComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TACListInLTENTNComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TACListInLTENTNComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTACListInLTENTNComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TACListInLTENTNComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TACListInLTENTNComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TACListInLTENTNComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TACListInLTENTNComplete")
}
func (v *TACListInLTENTNComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TACListInLTENTNComplete")
}
func (v *TACListInLTENTNComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTACListInLTENTNComplete(v, &s)
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
func (v *TACListInLTENTNComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TACListInLTENTNComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERTACListInLTENTNTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIBroadcastComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIBroadcastComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIBroadcastComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIBroadcastComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIBroadcastComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIBroadcastComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIBroadcastComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIBroadcastComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIBroadcastComplete")
}
func (v *TAIBroadcastComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIBroadcastComplete")
}
func (v *TAIBroadcastComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIBroadcastComplete(v, &s)
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
func (v *TAIBroadcastComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIBroadcastComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIBroadcastTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAICancelledComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAICancelledComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAICancelledComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAICancelledComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAICancelledComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAICancelledComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAICancelledComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAICancelledComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAICancelledComplete")
}
func (v *TAICancelledComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAICancelledComplete")
}
func (v *TAICancelledComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAICancelledComplete(v, &s)
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
func (v *TAICancelledComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAICancelledComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAICancelledTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListForRestartComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListForRestartComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListForRestartComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListForRestartComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListForRestartComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListForRestartComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListForRestartComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListForRestartComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListForRestartComplete")
}
func (v *TAIListForRestartComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListForRestartComplete")
}
func (v *TAIListForRestartComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListForRestartComplete(v, &s)
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
func (v *TAIListForRestartComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListForRestartComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIListForRestartTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforMDTComplete")
}
func (v *TAIListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforMDTComplete")
}
func (v *TAIListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforMDTComplete(v, &s)
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
func (v *TAIListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforQMCComplete")
}
func (v *TAIListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforQMCComplete")
}
func (v *TAIListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforQMCComplete(v, &s)
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
func (v *TAIListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAIListforWarningComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListforWarningComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListforWarningComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListforWarningComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListforWarningComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListforWarningComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListforWarningComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListforWarningComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListforWarningComplete")
}
func (v *TAIListforWarningComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListforWarningComplete")
}
func (v *TAIListforWarningComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListforWarningComplete(v, &s)
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
func (v *TAIListforWarningComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListforWarningComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIListforWarningTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAListforMDTComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAListforMDTComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAListforMDTComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAListforMDTComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAListforMDTComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAListforMDTComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAListforMDTComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAListforMDTComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAListforMDTComplete")
}
func (v *TAListforMDTComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAListforMDTComplete")
}
func (v *TAListforMDTComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAListforMDTComplete(v, &s)
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
func (v *TAListforMDTComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAListforMDTComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERTAListforMDTTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TAListforQMCComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAListforQMCComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAListforQMCComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAListforQMCComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAListforQMCComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAListforQMCComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAListforQMCComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAListforQMCComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAListforQMCComplete")
}
func (v *TAListforQMCComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAListforQMCComplete")
}
func (v *TAListforQMCComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAListforQMCComplete(v, &s)
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
func (v *TAListforQMCComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAListforQMCComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERTAListforQMCTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEHistoryInformationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEHistoryInformationComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEHistoryInformationComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEHistoryInformationComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEHistoryInformationComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEHistoryInformationComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEHistoryInformationComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEHistoryInformationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEHistoryInformationComplete")
}
func (v *UEHistoryInformationComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEHistoryInformationComplete")
}
func (v *UEHistoryInformationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEHistoryInformationComplete(v, &s)
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
func (v *UEHistoryInformationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEHistoryInformationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s42.BridgeMarshalAPERUEHistoryInformationTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UserLocationInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UserLocationInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UserLocationInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UserLocationInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUserLocationInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UserLocationInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UserLocationInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UserLocationInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UserLocationInformation")
}
func (v *UserLocationInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UserLocationInformation")
}
func (v *UserLocationInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUserLocationInformation(v, &s)
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
func (v *UserLocationInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UserLocationInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WLANMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WLANMeasConfigNameListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWLANMeasConfigNameListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WLANMeasConfigNameListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WLANMeasConfigNameListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func (v *WLANMeasConfigNameListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func (v *WLANMeasConfigNameListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWLANMeasConfigNameListComplete(v, &s)
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
func (v *WLANMeasConfigNameListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WLANMeasConfigNameListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s13.BridgeMarshalAPERWLANMeasConfigNameListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TACListInLTENTNComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TACListInLTENTNComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TACListInLTENTNComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTACListInLTENTNComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TACListInLTENTNComplete{}
		return report, aper.OperationError(err, "TACListInLTENTNComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TACListInLTENTNComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIBroadcastComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIBroadcastComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIBroadcastComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIBroadcastComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIBroadcastComplete{}
		return report, aper.OperationError(err, "TAIBroadcastComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIBroadcastComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAICancelledComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAICancelledComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAICancelledComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAICancelledComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAICancelledComplete{}
		return report, aper.OperationError(err, "TAICancelledComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAICancelledComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListForRestartComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListForRestartComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListForRestartComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListForRestartComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListForRestartComplete{}
		return report, aper.OperationError(err, "TAIListForRestartComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListForRestartComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforMDTComplete{}
		return report, aper.OperationError(err, "TAIListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforQMCComplete{}
		return report, aper.OperationError(err, "TAIListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListforWarningComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListforWarningComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListforWarningComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListforWarningComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListforWarningComplete{}
		return report, aper.OperationError(err, "TAIListforWarningComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListforWarningComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAListforMDTComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAListforMDTComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAListforMDTComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAListforMDTComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAListforMDTComplete{}
		return report, aper.OperationError(err, "TAListforMDTComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAListforMDTComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAListforQMCComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAListforQMCComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAListforQMCComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAListforQMCComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAListforQMCComplete{}
		return report, aper.OperationError(err, "TAListforQMCComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAListforQMCComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEHistoryInformationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEHistoryInformationComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEHistoryInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEHistoryInformationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEHistoryInformationComplete{}
		return report, aper.OperationError(err, "UEHistoryInformationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEHistoryInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UserLocationInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UserLocationInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UserLocationInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUserLocationInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UserLocationInformation{}
		return report, aper.OperationError(err, "UserLocationInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UserLocationInformation")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WLANMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WLANMeasConfigNameListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWLANMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WLANMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasConfigNameListComplete")
}

// MarshalAPERTACListInLTENTN encodes a complete named list.
func MarshalAPERTACListInLTENTN(v TACListInLTENTNComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListforMDT encodes a complete named list.
func MarshalAPERTAIListforMDT(v TAIListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListforWarning encodes a complete named list.
func MarshalAPERTAIListforWarning(v TAIListforWarningComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIBroadcast encodes a complete named list.
func MarshalAPERTAIBroadcast(v TAIBroadcastComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAICancelled encodes a complete named list.
func MarshalAPERTAICancelled(v TAICancelledComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAListforMDT encodes a complete named list.
func MarshalAPERTAListforMDT(v TAListforMDTComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAListforQMC encodes a complete named list.
func MarshalAPERTAListforQMC(v TAListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListforQMC encodes a complete named list.
func MarshalAPERTAIListforQMC(v TAIListforQMCComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERTAIListForRestart encodes a complete named list.
func MarshalAPERTAIListForRestart(v TAIListForRestartComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEHistoryInformation encodes a complete named list.
func MarshalAPERUEHistoryInformation(v UEHistoryInformationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERWLANMeasConfigNameList encodes a complete named list.
func MarshalAPERWLANMeasConfigNameList(v WLANMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERTACListInLTENTN decodes a complete named list.
func UnmarshalAPERTACListInLTENTN(data []byte, options ...aper.DecodeOption) (TACListInLTENTNComplete, aper.DecodeReport, error) {
	var v TACListInLTENTNComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListforMDT decodes a complete named list.
func UnmarshalAPERTAIListforMDT(data []byte, options ...aper.DecodeOption) (TAIListforMDTComplete, aper.DecodeReport, error) {
	var v TAIListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListforWarning decodes a complete named list.
func UnmarshalAPERTAIListforWarning(data []byte, options ...aper.DecodeOption) (TAIListforWarningComplete, aper.DecodeReport, error) {
	var v TAIListforWarningComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIBroadcast decodes a complete named list.
func UnmarshalAPERTAIBroadcast(data []byte, options ...aper.DecodeOption) (TAIBroadcastComplete, aper.DecodeReport, error) {
	var v TAIBroadcastComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAICancelled decodes a complete named list.
func UnmarshalAPERTAICancelled(data []byte, options ...aper.DecodeOption) (TAICancelledComplete, aper.DecodeReport, error) {
	var v TAICancelledComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAListforMDT decodes a complete named list.
func UnmarshalAPERTAListforMDT(data []byte, options ...aper.DecodeOption) (TAListforMDTComplete, aper.DecodeReport, error) {
	var v TAListforMDTComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAListforQMC decodes a complete named list.
func UnmarshalAPERTAListforQMC(data []byte, options ...aper.DecodeOption) (TAListforQMCComplete, aper.DecodeReport, error) {
	var v TAListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListforQMC decodes a complete named list.
func UnmarshalAPERTAIListforQMC(data []byte, options ...aper.DecodeOption) (TAIListforQMCComplete, aper.DecodeReport, error) {
	var v TAIListforQMCComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERTAIListForRestart decodes a complete named list.
func UnmarshalAPERTAIListForRestart(data []byte, options ...aper.DecodeOption) (TAIListForRestartComplete, aper.DecodeReport, error) {
	var v TAIListForRestartComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEHistoryInformation decodes a complete named list.
func UnmarshalAPERUEHistoryInformation(data []byte, options ...aper.DecodeOption) (UEHistoryInformationComplete, aper.DecodeReport, error) {
	var v UEHistoryInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERWLANMeasConfigNameList decodes a complete named list.
func UnmarshalAPERWLANMeasConfigNameList(data []byte, options ...aper.DecodeOption) (WLANMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v WLANMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UplinkNASTransport represents the ASN.1 type UplinkNASTransport (SEQUENCE).
type UplinkNASTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s32.UplinkNASTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ResetAcknowledge represents the ASN.1 type ResetAcknowledge (SEQUENCE).
type ResetAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ResetAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// S1SetupRequest represents the ASN.1 type S1SetupRequest (SEQUENCE).
type S1SetupRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s43.S1SetupRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UplinkS1cdma2000tunnelling represents the ASN.1 type UplinkS1cdma2000tunnelling (SEQUENCE).
type UplinkS1cdma2000tunnelling struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s21.UplinkS1cdma2000tunnellingIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// PWSRestartIndication represents the ASN.1 type PWSRestartIndication (SEQUENCE).
type PWSRestartIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PWSRestartIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                            `asn1:"-" json:"-"`
	extCount         int64                           `asn1:"-" json:"-"`
	extPresent       []bool                          `asn1:"-" json:"-"`
	extData          [][]byte                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UplinkUEAssociatedLPPaTransport represents the ASN.1 type UplinkUEAssociatedLPPaTransport (SEQUENCE).
type UplinkUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UplinkUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                           `asn1:"-" json:"-"`
	extCount         int64                                          `asn1:"-" json:"-"`
	extPresent       []bool                                         `asn1:"-" json:"-"`
	extData          [][]byte                                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UplinkNonUEAssociatedLPPaTransport represents the ASN.1 type UplinkNonUEAssociatedLPPaTransport (SEQUENCE).
type UplinkNonUEAssociatedLPPaTransport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UplinkNonUEAssociatedLPPaTransportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// TAIListComplete carries a complete TAIList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type TAIListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s33.TAIList
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *TAIListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s33.BridgeMarshalAPERTAIListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes TAIList from APER format.
func (v *TAIListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TAIList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TAIListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	bb.EnterComponent("TAIList")
	value, err := BridgeUnmarshalAPERTAIListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	padding, err := aper.CaptureFinalBits(bb, "TAIList")
	if err != nil {
		return runtime.WrapDecodePath(err, "TAIList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERTAIList encodes a TAIList list to APER.
func BridgeMarshalAPERTAIList(list TAIListComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPERTAIList decodes a TAIList list from APER.
func BridgeUnmarshalAPERTAIList(data []byte) (TAIListComplete, error) {
	var value TAIListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERTAIListFrom decodes a TAIList list from bb.
func BridgeUnmarshalAPERTAIListFrom(bb *aper.BitBuffer) (s33.TAIList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s33.BridgeAsn1cAPERTAIListListValue
	if err := BridgeUnmarshalAPERTAIListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERTAIListInto(v *s33.BridgeAsn1cAPERTAIListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s33.TAIList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s33.TAIItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s33.BridgeTAIItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkNASTransport to APER format.
func (v *UplinkNASTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkNASTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s32.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkNASTransport from APER format.
func (v *UplinkNASTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UplinkNASTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UplinkNASTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	bb.EnterComponent("UplinkNASTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkNASTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkNASTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UplinkNASTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkNASTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s32.UplinkNASTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s32.UplinkNASTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s32.BridgeUplinkNASTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// UEAssociatedLogicalS1ConnectionListResComplete carries a complete UEAssociatedLogicalS1ConnectionListRes encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEAssociatedLogicalS1ConnectionListResComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s36.UEAssociatedLogicalS1ConnectionListRes
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s36.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEAssociatedLogicalS1ConnectionListRes from APER format.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEAssociatedLogicalS1ConnectionListRes with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEAssociatedLogicalS1ConnectionListResComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	bb.EnterComponent("UEAssociatedLogicalS1ConnectionListRes")
	value, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionListRes")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListRes")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListRes encodes a UEAssociatedLogicalS1ConnectionListRes list to APER.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListRes(list UEAssociatedLogicalS1ConnectionListResComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes decodes a UEAssociatedLogicalS1ConnectionListRes list from APER.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListRes(data []byte) (UEAssociatedLogicalS1ConnectionListResComplete, error) {
	var value UEAssociatedLogicalS1ConnectionListResComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom decodes a UEAssociatedLogicalS1ConnectionListRes list from bb.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResFrom(bb *aper.BitBuffer) (s36.UEAssociatedLogicalS1ConnectionListRes, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s36.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue
	if err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResInto(v *s36.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s36.UEAssociatedLogicalS1ConnectionListRes, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ResetAcknowledge to APER format.
func (v *ResetAcknowledge) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResetAcknowledge) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ResetAcknowledge from APER format.
func (v *ResetAcknowledge) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResetAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResetAcknowledge) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	bb.EnterComponent("ResetAcknowledge")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResetAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResetAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResetAcknowledge) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ResetAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ResetAcknowledgeIEField
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

// UEAssociatedLogicalS1ConnectionListResAckComplete carries a complete UEAssociatedLogicalS1ConnectionListResAck encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type UEAssociatedLogicalS1ConnectionListResAckComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s36.UEAssociatedLogicalS1ConnectionListResAck
	perPadding       aper.CompletePadding `json:"-"`
}

func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s36.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes UEAssociatedLogicalS1ConnectionListResAck from APER format.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEAssociatedLogicalS1ConnectionListResAck with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	bb.EnterComponent("UEAssociatedLogicalS1ConnectionListResAck")
	value, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEAssociatedLogicalS1ConnectionListResAck")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAck encodes a UEAssociatedLogicalS1ConnectionListResAck list to APER.
func BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAck(list UEAssociatedLogicalS1ConnectionListResAckComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck decodes a UEAssociatedLogicalS1ConnectionListResAck list from APER.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck(data []byte) (UEAssociatedLogicalS1ConnectionListResAckComplete, error) {
	var value UEAssociatedLogicalS1ConnectionListResAckComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom decodes a UEAssociatedLogicalS1ConnectionListResAck list from bb.
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(bb *aper.BitBuffer) (s36.UEAssociatedLogicalS1ConnectionListResAck, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s36.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue
	if err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckInto(v *s36.BridgeAsn1cAPERUEAssociatedLogicalS1ConnectionListResAckListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s36.UEAssociatedLogicalS1ConnectionListResAck, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s35.UEAssociatedLogicalS1ConnectionItemResAckIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s35.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes S1SetupRequest to APER format.
func (v *S1SetupRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *S1SetupRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s43.BridgeS1SetupRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes S1SetupRequest from APER format.
func (v *S1SetupRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes S1SetupRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *S1SetupRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupRequest")
	}
	bb.EnterComponent("S1SetupRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1SetupRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "S1SetupRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "S1SetupRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *S1SetupRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = S1SetupRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s43.S1SetupRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s43.S1SetupRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s43.BridgeS1SetupRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkS1cdma2000tunnelling to APER format.
func (v *UplinkS1cdma2000tunnelling) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkS1cdma2000tunnelling from APER format.
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UplinkS1cdma2000tunnelling with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	bb.EnterComponent("UplinkS1cdma2000tunnelling")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkS1cdma2000tunnelling")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkS1cdma2000tunnelling")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UplinkS1cdma2000tunnelling) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkS1cdma2000tunnelling{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s21.UplinkS1cdma2000tunnellingIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s21.UplinkS1cdma2000tunnellingIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes PWSRestartIndication to APER format.
func (v *PWSRestartIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PWSRestartIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes PWSRestartIndication from APER format.
func (v *PWSRestartIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PWSRestartIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PWSRestartIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PWSRestartIndication")
	}
	bb.EnterComponent("PWSRestartIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PWSRestartIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "PWSRestartIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "PWSRestartIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PWSRestartIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PWSRestartIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PWSRestartIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PWSRestartIndicationIEField
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

// MarshalAPER encodes UplinkUEAssociatedLPPaTransport to APER format.
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkUEAssociatedLPPaTransport from APER format.
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UplinkUEAssociatedLPPaTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("UplinkUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkUEAssociatedLPPaTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UplinkUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkUEAssociatedLPPaTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UplinkUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UplinkUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UplinkNonUEAssociatedLPPaTransport to APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UplinkNonUEAssociatedLPPaTransport from APER format.
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UplinkNonUEAssociatedLPPaTransport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	bb.EnterComponent("UplinkNonUEAssociatedLPPaTransport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	padding, err := aper.CaptureFinalBits(bb, "UplinkNonUEAssociatedLPPaTransport")
	if err != nil {
		return runtime.WrapDecodePath(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UplinkNonUEAssociatedLPPaTransport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UplinkNonUEAssociatedLPPaTransport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UplinkNonUEAssociatedLPPaTransportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UplinkNonUEAssociatedLPPaTransportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUplinkNonUEAssociatedLPPaTransportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *PWSRestartIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "PWSRestartIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "PWSRestartIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PWSRestartIndication) WithoutReplay() PWSRestartIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero PWSRestartIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResetAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResetAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ResetAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResetAcknowledge) WithoutReplay() ResetAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ResetAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *S1SetupRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "S1SetupRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "S1SetupRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v S1SetupRequest) WithoutReplay() S1SetupRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero S1SetupRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TAIListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TAIListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TAIListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TAIListComplete) WithoutReplay() TAIListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TAIListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResAckComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResAckComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAssociatedLogicalS1ConnectionListResAckComplete) WithoutReplay() UEAssociatedLogicalS1ConnectionListResAckComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAssociatedLogicalS1ConnectionListResAckComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEAssociatedLogicalS1ConnectionListResComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEAssociatedLogicalS1ConnectionListResComplete) WithoutReplay() UEAssociatedLogicalS1ConnectionListResComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEAssociatedLogicalS1ConnectionListResComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkNASTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkNASTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkNASTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkNASTransport) WithoutReplay() UplinkNASTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkNASTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkNonUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkNonUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkNonUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkNonUEAssociatedLPPaTransport) WithoutReplay() UplinkNonUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkNonUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkS1cdma2000tunnelling) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkS1cdma2000tunnelling", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkS1cdma2000tunnelling", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkS1cdma2000tunnelling) WithoutReplay() UplinkS1cdma2000tunnelling {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkS1cdma2000tunnelling
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UplinkUEAssociatedLPPaTransport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UplinkUEAssociatedLPPaTransport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UplinkUEAssociatedLPPaTransport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UplinkUEAssociatedLPPaTransport) WithoutReplay() UplinkUEAssociatedLPPaTransport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UplinkUEAssociatedLPPaTransport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PWSRestartIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PWSRestartIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PWSRestartIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PWSRestartIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PWSRestartIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PWSRestartIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PWSRestartIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResetAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResetAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResetAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *S1SetupRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *S1SetupRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("S1SetupRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("S1SetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *S1SetupRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("S1SetupRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("S1SetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkNASTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkNASTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkNASTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNASTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkNonUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkNonUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkNonUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkNonUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkS1cdma2000tunnelling) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkS1cdma2000tunnelling) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkS1cdma2000tunnelling) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkS1cdma2000tunnelling.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UplinkUEAssociatedLPPaTransport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UplinkUEAssociatedLPPaTransport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UplinkUEAssociatedLPPaTransport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UplinkUEAssociatedLPPaTransport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *PWSRestartIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "PWSRestartIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *PWSRestartIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PWSRestartIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPWSRestartIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "PWSRestartIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "PWSRestartIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *PWSRestartIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "PWSRestartIndication")
}
func (v *PWSRestartIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "PWSRestartIndication")
}
func (v *PWSRestartIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPWSRestartIndication(v, &s)
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
func (v *PWSRestartIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *PWSRestartIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ResetAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ResetAcknowledge")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ResetAcknowledge) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResetAcknowledge")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APResetAcknowledge(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ResetAcknowledge")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ResetAcknowledge")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ResetAcknowledge) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ResetAcknowledge")
}
func (v *ResetAcknowledge) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ResetAcknowledge")
}
func (v *ResetAcknowledge) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APResetAcknowledge(v, &s)
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
func (v *ResetAcknowledge) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ResetAcknowledge) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *S1SetupRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "S1SetupRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *S1SetupRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "S1SetupRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APS1SetupRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "S1SetupRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "S1SetupRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *S1SetupRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "S1SetupRequest")
}
func (v *S1SetupRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "S1SetupRequest")
}
func (v *S1SetupRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APS1SetupRequest(v, &s)
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
func (v *S1SetupRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *S1SetupRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TAIListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TAIListComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TAIListComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TAIListComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTAIListComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TAIListComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TAIListComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TAIListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TAIListComplete")
}
func (v *TAIListComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TAIListComplete")
}
func (v *TAIListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTAIListComplete(v, &s)
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
func (v *TAIListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TAIListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s33.BridgeMarshalAPERTAIListTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAssociatedLogicalS1ConnectionListResAckComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAckComplete(v, &s)
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
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s36.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResAckTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEAssociatedLogicalS1ConnectionListResComplete")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResComplete(v, &s)
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
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEAssociatedLogicalS1ConnectionListResComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
	if err := s36.BridgeMarshalAPERUEAssociatedLogicalS1ConnectionListResTo(v.Value, bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UplinkNASTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkNASTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkNASTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkNASTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkNASTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkNASTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkNASTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkNASTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkNASTransport")
}
func (v *UplinkNASTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkNASTransport")
}
func (v *UplinkNASTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkNASTransport(v, &s)
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
func (v *UplinkNASTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkNASTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkNonUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkNonUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkNonUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkNonUEAssociatedLPPaTransport(v, &s)
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
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkNonUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkS1cdma2000tunnelling) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkS1cdma2000tunnelling")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkS1cdma2000tunnelling(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkS1cdma2000tunnelling")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkS1cdma2000tunnelling(v, &s)
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
func (v *UplinkS1cdma2000tunnelling) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkS1cdma2000tunnelling) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UplinkUEAssociatedLPPaTransport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UplinkUEAssociatedLPPaTransport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UplinkUEAssociatedLPPaTransport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUplinkUEAssociatedLPPaTransport(v, &s)
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
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UplinkUEAssociatedLPPaTransport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *PWSRestartIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PWSRestartIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded PWSRestartIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPWSRestartIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = PWSRestartIndication{}
		return report, aper.OperationError(err, "PWSRestartIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PWSRestartIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *ResetAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResetAcknowledge")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ResetAcknowledge
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APResetAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ResetAcknowledge{}
		return report, aper.OperationError(err, "ResetAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResetAcknowledge")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *S1SetupRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "S1SetupRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded S1SetupRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APS1SetupRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = S1SetupRequest{}
		return report, aper.OperationError(err, "S1SetupRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "S1SetupRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TAIListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TAIListComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TAIListComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTAIListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TAIListComplete{}
		return report, aper.OperationError(err, "TAIListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TAIListComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAssociatedLogicalS1ConnectionListResAckComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAssociatedLogicalS1ConnectionListResAckComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAckComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAssociatedLogicalS1ConnectionListResAckComplete{}
		return report, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResAckComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAssociatedLogicalS1ConnectionListResAckComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEAssociatedLogicalS1ConnectionListResComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEAssociatedLogicalS1ConnectionListResComplete
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEAssociatedLogicalS1ConnectionListResComplete{}
		return report, aper.OperationError(err, "UEAssociatedLogicalS1ConnectionListResComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEAssociatedLogicalS1ConnectionListResComplete")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkNASTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkNASTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkNASTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkNASTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkNASTransport{}
		return report, aper.OperationError(err, "UplinkNASTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkNASTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkNonUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkNonUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkNonUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkNonUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkNonUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkNonUEAssociatedLPPaTransport")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkS1cdma2000tunnelling) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkS1cdma2000tunnelling")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkS1cdma2000tunnelling
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkS1cdma2000tunnelling(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkS1cdma2000tunnelling{}
		return report, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkS1cdma2000tunnelling")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UplinkUEAssociatedLPPaTransport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UplinkUEAssociatedLPPaTransport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UplinkUEAssociatedLPPaTransport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUplinkUEAssociatedLPPaTransport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UplinkUEAssociatedLPPaTransport{}
		return report, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UplinkUEAssociatedLPPaTransport")
}

// MarshalAPERTAIList encodes a complete named list.
func MarshalAPERTAIList(v TAIListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListRes encodes a complete named list.
func MarshalAPERUEAssociatedLogicalS1ConnectionListRes(v UEAssociatedLogicalS1ConnectionListResComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERUEAssociatedLogicalS1ConnectionListResAck encodes a complete named list.
func MarshalAPERUEAssociatedLogicalS1ConnectionListResAck(v UEAssociatedLogicalS1ConnectionListResAckComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERTAIList decodes a complete named list.
func UnmarshalAPERTAIList(data []byte, options ...aper.DecodeOption) (TAIListComplete, aper.DecodeReport, error) {
	var v TAIListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes decodes a complete named list.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListRes(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResComplete, aper.DecodeReport, error) {
	var v UEAssociatedLogicalS1ConnectionListResComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck decodes a complete named list.
func UnmarshalAPERUEAssociatedLogicalS1ConnectionListResAck(data []byte, options ...aper.DecodeOption) (UEAssociatedLogicalS1ConnectionListResAckComplete, aper.DecodeReport, error) {
	var v UEAssociatedLogicalS1ConnectionListResAckComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

type ERABModificationIndicationIEValue struct {
	id                                     s00.ProtocolIEID
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	rowMMEUES1APID                         *s00.MMEUES1APID
	rowENBUES1APID                         *s00.ENBUES1APID
	rowERABToBeModifiedListBearerModInd    *s17.ERABToBeModifiedListBearerModInd
	rowERABNotToBeModifiedListBearerModInd *s16.ERABNotToBeModifiedListBearerModInd
	rowCSGMembershipInfo                   *s14.CSGMembershipInfo
	rowTunnelInformationForBBF             *s35.TunnelInformation
	rowSecondaryRATDataUsageReportList     *s28.SecondaryRATDataUsageReportList
	rowUserLocationInformation             *UserLocationInformation
}

func (v ERABModificationIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(199):
		return v.rowERABToBeModifiedListBearerModInd != nil
	case s00.ProtocolIEID(201):
		return v.rowERABNotToBeModifiedListBearerModInd != nil
	case s00.ProtocolIEID(226):
		return v.rowCSGMembershipInfo != nil
	case s00.ProtocolIEID(176):
		return v.rowTunnelInformationForBBF != nil
	case s00.ProtocolIEID(264):
		return v.rowSecondaryRATDataUsageReportList != nil
	case s00.ProtocolIEID(189):
		return v.rowUserLocationInformation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ERABModificationIndicationIEValue and reports whether the opaque alternative is selected.
func (v *ERABModificationIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ERABModificationIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABModificationIndicationIEs"}}
}
func (ERABModificationIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(199):
		return aper.UnknownSelector
	case s00.ProtocolIEID(201):
		return aper.UnknownSelector
	case s00.ProtocolIEID(226):
		return aper.UnknownSelector
	case s00.ProtocolIEID(176):
		return aper.UnknownSelector
	case s00.ProtocolIEID(264):
		return aper.UnknownSelector
	case s00.ProtocolIEID(189):
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
	case s00.ProtocolIEID(200):
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

// AsMMEUES1APID returns the selected MMEUES1APID value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsERABToBeModifiedListBearerModInd returns the selected ERABToBeModifiedListBearerModInd value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsERABToBeModifiedListBearerModInd() (*s17.ERABToBeModifiedListBearerModInd, bool) {
	if v == nil || v.id != s00.ProtocolIEID(199) || v.rowERABToBeModifiedListBearerModInd == nil {
		return nil, false
	}
	return v.rowERABToBeModifiedListBearerModInd, true
}

// AsERABNotToBeModifiedListBearerModInd returns the selected ERABNotToBeModifiedListBearerModInd value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsERABNotToBeModifiedListBearerModInd() (*s16.ERABNotToBeModifiedListBearerModInd, bool) {
	if v == nil || v.id != s00.ProtocolIEID(201) || v.rowERABNotToBeModifiedListBearerModInd == nil {
		return nil, false
	}
	return v.rowERABNotToBeModifiedListBearerModInd, true
}

// AsCSGMembershipInfo returns the selected CSGMembershipInfo value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsCSGMembershipInfo() (*s14.CSGMembershipInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(226) || v.rowCSGMembershipInfo == nil {
		return nil, false
	}
	return v.rowCSGMembershipInfo, true
}

// AsTunnelInformationForBBF returns the selected TunnelInformationForBBF value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsTunnelInformationForBBF() (*s35.TunnelInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(176) || v.rowTunnelInformationForBBF == nil {
		return nil, false
	}
	return v.rowTunnelInformationForBBF, true
}

// AsSecondaryRATDataUsageReportList returns the selected SecondaryRATDataUsageReportList value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsSecondaryRATDataUsageReportList() (*s28.SecondaryRATDataUsageReportList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(264) || v.rowSecondaryRATDataUsageReportList == nil {
		return nil, false
	}
	return v.rowSecondaryRATDataUsageReportList, true
}

// AsUserLocationInformation returns the selected UserLocationInformation value of ERABModificationIndicationIEValue and reports whether that alternative is active.
func (v *ERABModificationIndicationIEValue) AsUserLocationInformation() (*UserLocationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(189) || v.rowUserLocationInformation == nil {
		return nil, false
	}
	return v.rowUserLocationInformation, true
}
func (v ERABModificationIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ERABModificationIndicationIEValue, error) {
	out := ERABModificationIndicationIEValue{id: id}
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
	case s00.ProtocolIEID(199):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s40.BridgeUnmarshalAPERERABToBeModifiedListBearerModIndFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeModifiedListBearerModInd:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeModifiedListBearerModInd = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(201):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s39.BridgeUnmarshalAPERERABNotToBeModifiedListBearerModIndFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABNotToBeModifiedListBearerModInd:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABNotToBeModifiedListBearerModInd = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(226):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.CSGMembershipInfo
		child := scope
		if err := s14.BridgeCSGMembershipInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CSGMembershipInfo")
		if err != nil {
			return out, err
		}
		*s14.BridgeCSGMembershipInfoFieldPerPadding(&value) = padding
		*s14.BridgeCSGMembershipInfoFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCSGMembershipInfoFieldReceivedBytes(&value))
		*s14.BridgeCSGMembershipInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCSGMembershipInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(176):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.TunnelInformation
		child := scope
		if err := s35.BridgeTunnelInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TunnelInformationForBBF:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TunnelInformation")
		if err != nil {
			return out, err
		}
		*s35.BridgeTunnelInformationFieldPerPadding(&value) = padding
		*s35.BridgeTunnelInformationFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeTunnelInformationFieldReceivedBytes(&value))
		*s35.BridgeTunnelInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTunnelInformationForBBF = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(264):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERSecondaryRATDataUsageReportListFrom(child)
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
	case s00.ProtocolIEID(189):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value UserLocationInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "UserLocationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UserLocationInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowUserLocationInformation = &value
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
func (v ERABModificationIndicationIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v ERABModificationIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-MME-UE-S1AP-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-eNB-UE-S1AP-ID:")
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
	case s00.ProtocolIEID(199):
		if v.rowERABToBeModifiedListBearerModInd == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-E-RABToBeModifiedListBearerModInd:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s40.ERABToBeModifiedListBearerModIndComplete{Value: *v.rowERABToBeModifiedListBearerModInd}
		candidate, err := s40.BridgeERABToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(201):
		if v.rowERABNotToBeModifiedListBearerModInd == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-E-RABNotToBeModifiedListBearerModInd:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s39.ERABNotToBeModifiedListBearerModIndComplete{Value: *v.rowERABNotToBeModifiedListBearerModInd}
		candidate, err := s39.BridgeERABNotToBeModifiedListBearerModIndCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(226):
		if v.rowCSGMembershipInfo == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-CSGMembershipInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCSGMembershipInfoMethodMarshalAPERBudget(v.rowCSGMembershipInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(176):
		if v.rowTunnelInformationForBBF == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-Tunnel-Information-for-BBF:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeTunnelInformationMethodMarshalAPERBudget(v.rowTunnelInformationForBBF, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(264):
		if v.rowSecondaryRATDataUsageReportList == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-SecondaryRATDataUsageReportList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.SecondaryRATDataUsageReportListComplete{Value: *v.rowSecondaryRATDataUsageReportList}
		candidate, err := s42.BridgeSecondaryRATDataUsageReportListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(189):
		if v.rowUserLocationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "E-RABModificationIndicationIEs.id-UserLocationInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowUserLocationInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ERABModificationIndicationIEValue:", v.id)
	}
}

type PWSRestartIndicationIEValue struct {
	id                               s00.ProtocolIEID
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           aper.OpaqueOpenType
	isOpaque                         bool
	rowECGIListForRestart            *s17.ECGIListForRestart
	rowGlobalENBID                   *s18.GlobalENBID
	rowTAIListForRestart             *s32.TAIListForRestart
	rowEmergencyAreaIDListForRestart *s00.EmergencyAreaIDListForRestart
}

func (v PWSRestartIndicationIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(182):
		return v.rowECGIListForRestart != nil
	case s00.ProtocolIEID(59):
		return v.rowGlobalENBID != nil
	case s00.ProtocolIEID(188):
		return v.rowTAIListForRestart != nil
	case s00.ProtocolIEID(190):
		return v.rowEmergencyAreaIDListForRestart != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PWSRestartIndicationIEValue and reports whether the opaque alternative is selected.
func (v *PWSRestartIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PWSRestartIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs"}}
}
func (PWSRestartIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(182):
		return aper.UnknownSelector
	case s00.ProtocolIEID(59):
		return aper.UnknownSelector
	case s00.ProtocolIEID(188):
		return aper.UnknownSelector
	case s00.ProtocolIEID(190):
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
	case s00.ProtocolIEID(189):
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

// AsECGIListForRestart returns the selected ECGIListForRestart value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsECGIListForRestart() (*s17.ECGIListForRestart, bool) {
	if v == nil || v.id != s00.ProtocolIEID(182) || v.rowECGIListForRestart == nil {
		return nil, false
	}
	return v.rowECGIListForRestart, true
}

// AsGlobalENBID returns the selected GlobalENBID value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsGlobalENBID() (*s18.GlobalENBID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(59) || v.rowGlobalENBID == nil {
		return nil, false
	}
	return v.rowGlobalENBID, true
}

// AsTAIListForRestart returns the selected TAIListForRestart value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsTAIListForRestart() (*s32.TAIListForRestart, bool) {
	if v == nil || v.id != s00.ProtocolIEID(188) || v.rowTAIListForRestart == nil {
		return nil, false
	}
	return v.rowTAIListForRestart, true
}

// AsEmergencyAreaIDListForRestart returns the selected EmergencyAreaIDListForRestart value of PWSRestartIndicationIEValue and reports whether that alternative is active.
func (v *PWSRestartIndicationIEValue) AsEmergencyAreaIDListForRestart() (*s00.EmergencyAreaIDListForRestart, bool) {
	if v == nil || v.id != s00.ProtocolIEID(190) || v.rowEmergencyAreaIDListForRestart == nil {
		return nil, false
	}
	return v.rowEmergencyAreaIDListForRestart, true
}
func (v PWSRestartIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PWSRestartIndicationIEValue, error) {
	out := PWSRestartIndicationIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(182):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s38.BridgeUnmarshalAPERECGIListForRestartFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ECGIListForRestart:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowECGIListForRestart = &value
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
	case s00.ProtocolIEID(188):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERTAIListForRestartFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TAIListForRestart:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowTAIListForRestart = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(190):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s41.BridgeUnmarshalAPEREmergencyAreaIDListForRestartFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EmergencyAreaIDListForRestart:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowEmergencyAreaIDListForRestart = &value
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
func (v PWSRestartIndicationIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PWSRestartIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(182):
		if v.rowECGIListForRestart == nil {
			return nil, fmt.Errorf("%s missing value", "PWSRestartIndicationIEs.id-ECGIListForRestart:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s38.ECGIListForRestartComplete{Value: *v.rowECGIListForRestart}
		candidate, err := s38.BridgeECGIListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(59):
		if v.rowGlobalENBID == nil {
			return nil, fmt.Errorf("%s missing value", "PWSRestartIndicationIEs.id-Global-ENB-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGlobalENBIDMethodMarshalAPERBudget(v.rowGlobalENBID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(188):
		if v.rowTAIListForRestart == nil {
			return nil, fmt.Errorf("%s missing value", "PWSRestartIndicationIEs.id-TAIListForRestart:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := TAIListForRestartComplete{Value: *v.rowTAIListForRestart}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(190):
		if v.rowEmergencyAreaIDListForRestart == nil {
			return nil, fmt.Errorf("%s missing value", "PWSRestartIndicationIEs.id-EmergencyAreaIDListForRestart:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s41.EmergencyAreaIDListForRestartComplete{Value: *v.rowEmergencyAreaIDListForRestart}
		candidate, err := s41.BridgeEmergencyAreaIDListForRestartCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PWSRestartIndicationIEValue:", v.id)
	}
}

type ResetAcknowledgeIEValue struct {
	id                                           s00.ProtocolIEID
	received                                     aper.WireSpan
	replay                                       aper.Snapshot
	opaque                                       aper.OpaqueOpenType
	isOpaque                                     bool
	rowUEAssociatedLogicalS1ConnectionListResAck *s36.UEAssociatedLogicalS1ConnectionListResAck
	rowCriticalityDiagnostics                    *s22.CriticalityDiagnostics
}

func (v ResetAcknowledgeIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(93):
		return v.rowUEAssociatedLogicalS1ConnectionListResAck != nil
	case s00.ProtocolIEID(58):
		return v.rowCriticalityDiagnostics != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ResetAcknowledgeIEValue and reports whether the opaque alternative is selected.
func (v *ResetAcknowledgeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ResetAcknowledgeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs"}}
}
func (ResetAcknowledgeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(93):
		return aper.UnknownSelector
	case s00.ProtocolIEID(58):
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

// AsUEAssociatedLogicalS1ConnectionListResAck returns the selected UEAssociatedLogicalS1ConnectionListResAck value of ResetAcknowledgeIEValue and reports whether that alternative is active.
func (v *ResetAcknowledgeIEValue) AsUEAssociatedLogicalS1ConnectionListResAck() (*s36.UEAssociatedLogicalS1ConnectionListResAck, bool) {
	if v == nil || v.id != s00.ProtocolIEID(93) || v.rowUEAssociatedLogicalS1ConnectionListResAck == nil {
		return nil, false
	}
	return v.rowUEAssociatedLogicalS1ConnectionListResAck, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value of ResetAcknowledgeIEValue and reports whether that alternative is active.
func (v *ResetAcknowledgeIEValue) AsCriticalityDiagnostics() (*s22.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(58) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v ResetAcknowledgeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResetAcknowledgeIEValue, error) {
	out := ResetAcknowledgeIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(93):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := BridgeUnmarshalAPERUEAssociatedLogicalS1ConnectionListResAckFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEAssociatedLogicalS1ConnectionListResAck:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowUEAssociatedLogicalS1ConnectionListResAck = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(58):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s22.CriticalityDiagnostics
		child := scope
		if err := s22.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s22.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s22.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s22.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		*s22.BridgeCriticalityDiagnosticsFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCriticalityDiagnostics = &value
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
func (v ResetAcknowledgeIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ResetAcknowledgeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(93):
		if v.rowUEAssociatedLogicalS1ConnectionListResAck == nil {
			return nil, fmt.Errorf("%s missing value", "ResetAcknowledgeIEs.id-UE-associatedLogicalS1-ConnectionListResAck:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := UEAssociatedLogicalS1ConnectionListResAckComplete{Value: *v.rowUEAssociatedLogicalS1ConnectionListResAck}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(58):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "ResetAcknowledgeIEs.id-CriticalityDiagnostics:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s22.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResetAcknowledgeIEValue:", v.id)
	}
}

type PWSRestartIndicationIETable struct{}

func PWSRestartIndicationIEs() PWSRestartIndicationIETable { return PWSRestartIndicationIETable{} }

// ID returns the ASN.1 object-set identity of PWSRestartIndicationIETable.
func (PWSRestartIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PWSRestartIndicationIETable.
func (PWSRestartIndicationIETable) Table() s00.PWSRestartIndicationIEValueIETable {
	return func() s00.PWSRestartIndicationIEValueIETable {
		sealed := s00.PWSRestartIndicationIEValueIETable{}
		*s00.BridgePWSRestartIndicationIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PWSRestartIndicationIETable) infoECGIListForRestart() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSRestartIndicationIEs().ID(), ID: s00.ProtocolIEID(182), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ECGIListForRestart"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs", Row: "id-ECGIListForRestart"}}}
}

// ECGIListForRestart returns the typed binding for the ECGIListForRestart row of PWSRestartIndicationIETable.
func (t PWSRestartIndicationIETable) ECGIListForRestart() PWSRestartIndicationECGIListForRestartIEBinding {
	return PWSRestartIndicationECGIListForRestartIEBinding{info: t.infoECGIListForRestart(), codec: func() s17.ECGIListForRestartValueCodec {
		sealed := s17.ECGIListForRestartValueCodec{}
		*s17.BridgeECGIListForRestartValueCodecFieldPath(&sealed) = "ECGIListForRestart"
		*s17.BridgeECGIListForRestartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.ECGIListForRestart, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.ECGIListForRestart
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ECGIListForRestart")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(182), raw)
			if err != nil {
				var empty s17.ECGIListForRestart
				return empty, runtime.WrapDecodePath(err, "ECGIListForRestart")
			}
			value, ok := decoded.AsECGIListForRestart()
			if !ok {
				var empty s17.ECGIListForRestart
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-ECGIListForRestart: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeECGIListForRestartValueCodecFieldEncode(&sealed) = func(value s17.ECGIListForRestart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(182), rowECGIListForRestart: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeECGIListForRestartValueCodecFieldCapture(&sealed) = func(v s17.ECGIListForRestart, options aper.DecodeState) (s17.ECGIListForRestart, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureS1APECGIListForRestart(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s17.BridgeECGIListForRestartValueCodecFieldCompare(&sealed) = func(v s17.ECGIListForRestart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APECGIListForRestart(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeECGIListForRestartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECGIListForRestart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.ECGIListForRestart) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(182), rowECGIListForRestart: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s17.ECGIListForRestart, bool) {
			return value.AsECGIListForRestart()
		}}
}
func (PWSRestartIndicationIETable) infoGlobalENBID() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSRestartIndicationIEs().ID(), ID: s00.ProtocolIEID(59), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Global-ENB-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs", Row: "id-Global-ENB-ID"}}}
}

// GlobalENBID returns the typed binding for the GlobalENBID row of PWSRestartIndicationIETable.
func (t PWSRestartIndicationIETable) GlobalENBID() PWSRestartIndicationGlobalENBIDIEBinding {
	return PWSRestartIndicationGlobalENBIDIEBinding{info: t.infoGlobalENBID(), codec: func() s18.GlobalENBIDValueCodec {
		sealed := s18.GlobalENBIDValueCodec{}
		*s18.BridgeGlobalENBIDValueCodecFieldPath(&sealed) = "GlobalENBID"
		*s18.BridgeGlobalENBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GlobalENBID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GlobalENBID")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(59), raw)
			if err != nil {
				var empty s18.GlobalENBID
				return empty, runtime.WrapDecodePath(err, "GlobalENBID")
			}
			value, ok := decoded.AsGlobalENBID()
			if !ok {
				var empty s18.GlobalENBID
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-Global-ENB-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGlobalENBIDValueCodecFieldEncode(&sealed) = func(value s18.GlobalENBID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s18.GlobalENBID) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(59), rowGlobalENBID: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s18.GlobalENBID, bool) { return value.AsGlobalENBID() }}
}
func (PWSRestartIndicationIETable) infoTAIListForRestart() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSRestartIndicationIEs().ID(), ID: s00.ProtocolIEID(188), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TAIListForRestart"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs", Row: "id-TAIListForRestart"}}}
}

// TAIListForRestart returns the typed binding for the TAIListForRestart row of PWSRestartIndicationIETable.
func (t PWSRestartIndicationIETable) TAIListForRestart() PWSRestartIndicationTAIListForRestartIEBinding {
	return PWSRestartIndicationTAIListForRestartIEBinding{info: t.infoTAIListForRestart(), codec: func() s32.TAIListForRestartValueCodec {
		sealed := s32.TAIListForRestartValueCodec{}
		*s32.BridgeTAIListForRestartValueCodecFieldPath(&sealed) = "TAIListForRestart"
		*s32.BridgeTAIListForRestartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAIListForRestart, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s32.TAIListForRestart
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAIListForRestart")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(188), raw)
			if err != nil {
				var empty s32.TAIListForRestart
				return empty, runtime.WrapDecodePath(err, "TAIListForRestart")
			}
			value, ok := decoded.AsTAIListForRestart()
			if !ok {
				var empty s32.TAIListForRestart
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-TAIListForRestart: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeTAIListForRestartValueCodecFieldEncode(&sealed) = func(value s32.TAIListForRestart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(188), rowTAIListForRestart: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeTAIListForRestartValueCodecFieldCapture(&sealed) = func(v s32.TAIListForRestart, options aper.DecodeState) (s32.TAIListForRestart, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAIListForRestart(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s32.BridgeTAIListForRestartValueCodecFieldCompare(&sealed) = func(v s32.TAIListForRestart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAIListForRestart(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s32.BridgeTAIListForRestartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListForRestart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s32.TAIListForRestart) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(188), rowTAIListForRestart: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s32.TAIListForRestart, bool) {
			return value.AsTAIListForRestart()
		}}
}
func (PWSRestartIndicationIETable) infoEmergencyAreaIDListForRestart() s00.FieldInfo {
	return s00.FieldInfo{Table: PWSRestartIndicationIEs().ID(), ID: s00.ProtocolIEID(190), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EmergencyAreaIDListForRestart"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PWSRestartIndicationIEs", Row: "id-EmergencyAreaIDListForRestart"}}}
}

// EmergencyAreaIDListForRestart returns the typed binding for the EmergencyAreaIDListForRestart row of PWSRestartIndicationIETable.
func (t PWSRestartIndicationIETable) EmergencyAreaIDListForRestart() PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding {
	return PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding{info: t.infoEmergencyAreaIDListForRestart(), codec: func() s00.EmergencyAreaIDListForRestartValueCodec {
		sealed := s00.EmergencyAreaIDListForRestartValueCodec{}
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldPath(&sealed) = "EmergencyAreaIDListForRestart"
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EmergencyAreaIDListForRestart, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EmergencyAreaIDListForRestart
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EmergencyAreaIDListForRestart")
			var zero PWSRestartIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(190), raw)
			if err != nil {
				var empty s00.EmergencyAreaIDListForRestart
				return empty, runtime.WrapDecodePath(err, "EmergencyAreaIDListForRestart")
			}
			value, ok := decoded.AsEmergencyAreaIDListForRestart()
			if !ok {
				var empty s00.EmergencyAreaIDListForRestart
				return empty, fmt.Errorf("binding PWSRestartIndicationIEs.id-EmergencyAreaIDListForRestart: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldEncode(&sealed) = func(value s00.EmergencyAreaIDListForRestart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PWSRestartIndicationIEValue{id: s00.ProtocolIEID(190), rowEmergencyAreaIDListForRestart: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldCapture(&sealed) = func(v s00.EmergencyAreaIDListForRestart, options aper.DecodeState) (s00.EmergencyAreaIDListForRestart, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEmergencyAreaIDListForRestart(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldCompare(&sealed) = func(v s00.EmergencyAreaIDListForRestart, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s02.BridgeCompareS1APEmergencyAreaIDListForRestart(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEmergencyAreaIDListForRestartValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaIDListForRestart"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EmergencyAreaIDListForRestart) PWSRestartIndicationIEValue {
			return PWSRestartIndicationIEValue{id: s00.ProtocolIEID(190), rowEmergencyAreaIDListForRestart: &value}
		}, get: func(value *PWSRestartIndicationIEValue) (*s00.EmergencyAreaIDListForRestart, bool) {
			return value.AsEmergencyAreaIDListForRestart()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PWSRestartIndicationIETable.
func (t PWSRestartIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PWSRestartIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(182):
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-ECGIListForRestart requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(59):
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Global-ENB-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(188):
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAIListForRestart requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(190):
		return PWSRestartIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-EmergencyAreaIDListForRestart requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PWSRestartIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PWSRestartIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return PWSRestartIndicationIEField{Id: id, Criticality: criticality, Value: PWSRestartIndicationIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ResetAcknowledgeIETable struct{}

func ResetAcknowledgeIEs() ResetAcknowledgeIETable { return ResetAcknowledgeIETable{} }

// ID returns the ASN.1 object-set identity of ResetAcknowledgeIETable.
func (ResetAcknowledgeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ResetAcknowledgeIETable.
func (ResetAcknowledgeIETable) Table() s00.ResetAcknowledgeIEValueIETable {
	return func() s00.ResetAcknowledgeIEValueIETable {
		sealed := s00.ResetAcknowledgeIEValueIETable{}
		*s00.BridgeResetAcknowledgeIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ResetAcknowledgeIETable) infoUEAssociatedLogicalS1ConnectionListResAck() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(93), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UE-associatedLogicalS1-ConnectionListResAck"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs", Row: "id-UE-associatedLogicalS1-ConnectionListResAck"}}}
}

// UEAssociatedLogicalS1ConnectionListResAck returns the typed binding for the UEAssociatedLogicalS1ConnectionListResAck row of ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) UEAssociatedLogicalS1ConnectionListResAck() ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding {
	return ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding{info: t.infoUEAssociatedLogicalS1ConnectionListResAck(), codec: func() s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
		sealed := s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec{}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldPath(&sealed) = "UEAssociatedLogicalS1ConnectionListResAck"
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEAssociatedLogicalS1ConnectionListResAck, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s36.UEAssociatedLogicalS1ConnectionListResAck
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAssociatedLogicalS1ConnectionListResAck")
			var zero ResetAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(93), raw)
			if err != nil {
				var empty s36.UEAssociatedLogicalS1ConnectionListResAck
				return empty, runtime.WrapDecodePath(err, "UEAssociatedLogicalS1ConnectionListResAck")
			}
			value, ok := decoded.AsUEAssociatedLogicalS1ConnectionListResAck()
			if !ok {
				var empty s36.UEAssociatedLogicalS1ConnectionListResAck
				return empty, fmt.Errorf("binding ResetAcknowledgeIEs.id-UE-associatedLogicalS1-ConnectionListResAck: no selected value")
			}
			return *value, nil
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldEncode(&sealed) = func(value s36.UEAssociatedLogicalS1ConnectionListResAck, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetAcknowledgeIEValue{id: s00.ProtocolIEID(93), rowUEAssociatedLogicalS1ConnectionListResAck: &value}).encodeFresh(fresh, budget)
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCapture(&sealed) = func(v s36.UEAssociatedLogicalS1ConnectionListResAck, options aper.DecodeState) (s36.UEAssociatedLogicalS1ConnectionListResAck, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListResAck(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldCompare(&sealed) = func(v s36.UEAssociatedLogicalS1ConnectionListResAck, root aper.Snapshot, budget aper.DecodeBudget,
		) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root,
				budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListResAck(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResAckValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionListResAck"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s36.UEAssociatedLogicalS1ConnectionListResAck) ResetAcknowledgeIEValue {
			return ResetAcknowledgeIEValue{id: s00.ProtocolIEID(93), rowUEAssociatedLogicalS1ConnectionListResAck: &value}
		}, get: func(value *ResetAcknowledgeIEValue) (*s36.UEAssociatedLogicalS1ConnectionListResAck, bool) {
			return value.AsUEAssociatedLogicalS1ConnectionListResAck()
		}}
}
func (ResetAcknowledgeIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetAcknowledgeIEs().ID(), ID: s00.ProtocolIEID(58), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetAcknowledgeIEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) CriticalityDiagnostics() ResetAcknowledgeCriticalityDiagnosticsIEBinding {
	return ResetAcknowledgeCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s22.CriticalityDiagnosticsValueCodec {
		sealed := s22.CriticalityDiagnosticsValueCodec{}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CriticalityDiagnostics")
			var zero ResetAcknowledgeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(58), raw)
			if err != nil {
				var empty s22.CriticalityDiagnostics
				return empty, runtime.WrapDecodePath(err, "CriticalityDiagnostics")
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s22.CriticalityDiagnostics
				return empty, fmt.Errorf("binding ResetAcknowledgeIEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s22.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s22.CriticalityDiagnostics, options aper.DecodeState) (s22.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureS1APCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s22.CriticalityDiagnostics, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s22.BridgeCompareS1APCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s22.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s22.CriticalityDiagnostics) ResetAcknowledgeIEValue {
			return ResetAcknowledgeIEValue{id: s00.ProtocolIEID(58), rowCriticalityDiagnostics: &value}
		}, get: func(value *ResetAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ResetAcknowledgeIETable.
func (t ResetAcknowledgeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResetAcknowledgeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(93):
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-associatedLogicalS1-ConnectionListResAck requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(58):
		return ResetAcknowledgeIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResetAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResetAcknowledgeIEField{}, aper.OperationError(err, "Opaque")
		}
		return ResetAcknowledgeIEField{Id: id, Criticality: criticality, Value: ResetAcknowledgeIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ECGIListForRestartCodec binds the complete APER value type.
func ECGIListForRestartCodec() s17.ECGIListForRestartValueCodec {
	return PWSRestartIndicationIEs().ECGIListForRestart().Codec()
}

// EmergencyAreaIDListForRestartCodec binds the complete APER value type.
func EmergencyAreaIDListForRestartCodec() s00.EmergencyAreaIDListForRestartValueCodec {
	return PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Codec()
}

// TACListInLTENTNCodec binds the complete source value type.
func TACListInLTENTNCodec() s01.TACListInLTENTNValueCodec {
	return func() s01.TACListInLTENTNValueCodec {
		sealed := s01.TACListInLTENTNValueCodec{}
		*s01.BridgeTACListInLTENTNValueCodecFieldPath(&sealed) = "TACListInLTENTN"
		*s01.BridgeTACListInLTENTNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TACListInLTENTN, error) {
			var complete TACListInLTENTNComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TACListInLTENTN
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeTACListInLTENTNValueCodecFieldEncode(&sealed) = func(value s00.TACListInLTENTN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TACListInLTENTNComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeTACListInLTENTNValueCodecFieldCapture(&sealed) = func(v s00.TACListInLTENTN, options aper.DecodeState) (s00.TACListInLTENTN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTACListInLTENTN(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTACListInLTENTNValueCodecFieldCompare(&sealed) = func(v s00.TACListInLTENTN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTACListInLTENTN(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeTACListInLTENTNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TACListInLTENTN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIBroadcastCodec binds the complete source value type.
func TAIBroadcastCodec() s32.TAIBroadcastValueCodec {
	return func() s32.TAIBroadcastValueCodec {
		sealed := s32.TAIBroadcastValueCodec{}
		*s32.BridgeTAIBroadcastValueCodecFieldPath(&sealed) = "TAIBroadcast"
		*s32.BridgeTAIBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAIBroadcast, error) {
			var complete TAIBroadcastComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.TAIBroadcast
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeTAIBroadcastValueCodecFieldEncode(&sealed) = func(value s32.TAIBroadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIBroadcastComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeTAIBroadcastValueCodecFieldCapture(&sealed) = func(v s32.TAIBroadcast, options aper.DecodeState) (s32.TAIBroadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAIBroadcast(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeTAIBroadcastValueCodecFieldCompare(&sealed) = func(v s32.TAIBroadcast, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAIBroadcast(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s32.BridgeTAIBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIBroadcast"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAICancelledCodec binds the complete source value type.
func TAICancelledCodec() s32.TAICancelledValueCodec {
	return func() s32.TAICancelledValueCodec {
		sealed := s32.TAICancelledValueCodec{}
		*s32.BridgeTAICancelledValueCodecFieldPath(&sealed) = "TAICancelled"
		*s32.BridgeTAICancelledValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAICancelled, error) {
			var complete TAICancelledComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.TAICancelled
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeTAICancelledValueCodecFieldEncode(&sealed) = func(value s32.TAICancelled, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAICancelledComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeTAICancelledValueCodecFieldCapture(&sealed) = func(v s32.TAICancelled, options aper.DecodeState) (s32.TAICancelled, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAICancelled(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeTAICancelledValueCodecFieldCompare(&sealed) = func(v s32.TAICancelled, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAICancelled(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s32.BridgeTAICancelledValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAICancelled"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListForRestartCodec binds the complete APER value type.
func TAIListForRestartCodec() s32.TAIListForRestartValueCodec {
	return PWSRestartIndicationIEs().TAIListForRestart().Codec()
}

// TAIListforMDTCodec binds the complete source value type.
func TAIListforMDTCodec() s32.TAIListforMDTValueCodec {
	return func() s32.TAIListforMDTValueCodec {
		sealed := s32.TAIListforMDTValueCodec{}
		*s32.BridgeTAIListforMDTValueCodecFieldPath(&sealed) = "TAIListforMDT"
		*s32.BridgeTAIListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAIListforMDT, error) {
			var complete TAIListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.TAIListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeTAIListforMDTValueCodecFieldEncode(&sealed) = func(value s32.TAIListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeTAIListforMDTValueCodecFieldCapture(&sealed) = func(v s32.TAIListforMDT, options aper.DecodeState) (s32.TAIListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAIListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeTAIListforMDTValueCodecFieldCompare(&sealed) = func(v s32.TAIListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAIListforMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s32.BridgeTAIListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListforQMCCodec binds the complete source value type.
func TAIListforQMCCodec() s32.TAIListforQMCValueCodec {
	return func() s32.TAIListforQMCValueCodec {
		sealed := s32.TAIListforQMCValueCodec{}
		*s32.BridgeTAIListforQMCValueCodecFieldPath(&sealed) = "TAIListforQMC"
		*s32.BridgeTAIListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAIListforQMC, error) {
			var complete TAIListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.TAIListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeTAIListforQMCValueCodecFieldEncode(&sealed) = func(value s32.TAIListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeTAIListforQMCValueCodecFieldCapture(&sealed) = func(v s32.TAIListforQMC, options aper.DecodeState) (s32.TAIListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAIListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeTAIListforQMCValueCodecFieldCompare(&sealed) = func(v s32.TAIListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAIListforQMC(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s32.BridgeTAIListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAIListforWarningCodec binds the complete source value type.
func TAIListforWarningCodec() s32.TAIListforWarningValueCodec {
	return func() s32.TAIListforWarningValueCodec {
		sealed := s32.TAIListforWarningValueCodec{}
		*s32.BridgeTAIListforWarningValueCodecFieldPath(&sealed) = "TAIListforWarning"
		*s32.BridgeTAIListforWarningValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.TAIListforWarning, error) {
			var complete TAIListforWarningComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s32.TAIListforWarning
				return zero, err
			}
			return complete.Value, nil
		}
		*s32.BridgeTAIListforWarningValueCodecFieldEncode(&sealed) = func(value s32.TAIListforWarning, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAIListforWarningComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s32.BridgeTAIListforWarningValueCodecFieldCapture(&sealed) = func(v s32.TAIListforWarning, options aper.DecodeState) (s32.TAIListforWarning, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APTAIListforWarning(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s32.BridgeTAIListforWarningValueCodecFieldCompare(&sealed) = func(v s32.TAIListforWarning, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APTAIListforWarning(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s32.BridgeTAIListforWarningValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIListforWarning"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAListforMDTCodec binds the complete source value type.
func TAListforMDTCodec() s01.TAListforMDTValueCodec {
	return func() s01.TAListforMDTValueCodec {
		sealed := s01.TAListforMDTValueCodec{}
		*s01.BridgeTAListforMDTValueCodecFieldPath(&sealed) = "TAListforMDT"
		*s01.BridgeTAListforMDTValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAListforMDT, error) {
			var complete TAListforMDTComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TAListforMDT
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeTAListforMDTValueCodecFieldEncode(&sealed) = func(value s00.TAListforMDT, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAListforMDTComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeTAListforMDTValueCodecFieldCapture(&sealed) = func(v s00.TAListforMDT, options aper.DecodeState) (s00.TAListforMDT, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTAListforMDT(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTAListforMDTValueCodecFieldCompare(&sealed) = func(v s00.TAListforMDT, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTAListforMDT(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeTAListforMDTValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAListforMDT"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TAListforQMCCodec binds the complete source value type.
func TAListforQMCCodec() s01.TAListforQMCValueCodec {
	return func() s01.TAListforQMCValueCodec {
		sealed := s01.TAListforQMCValueCodec{}
		*s01.BridgeTAListforQMCValueCodecFieldPath(&sealed) = "TAListforQMC"
		*s01.BridgeTAListforQMCValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TAListforQMC, error) {
			var complete TAListforQMCComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.TAListforQMC
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeTAListforQMCValueCodecFieldEncode(&sealed) = func(value s00.TAListforQMC, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := TAListforQMCComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeTAListforQMCValueCodecFieldCapture(&sealed) = func(v s00.TAListforQMC, options aper.DecodeState) (s00.TAListforQMC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTAListforQMC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeTAListforQMCValueCodecFieldCompare(&sealed) = func(v s00.TAListforQMC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTAListforQMC(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeTAListforQMCValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAListforQMC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEAssociatedLogicalS1ConnectionListResAckCodec binds the complete APER value type.
func UEAssociatedLogicalS1ConnectionListResAckCodec() s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
	return ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Codec()
}

// UEAssociatedLogicalS1ConnectionListResCodec binds the complete source value type.
func UEAssociatedLogicalS1ConnectionListResCodec() s36.UEAssociatedLogicalS1ConnectionListResValueCodec {
	return func() s36.UEAssociatedLogicalS1ConnectionListResValueCodec {
		sealed := s36.UEAssociatedLogicalS1ConnectionListResValueCodec{}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldPath(&sealed) = "UEAssociatedLogicalS1ConnectionListRes"
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEAssociatedLogicalS1ConnectionListRes, error) {
			var complete UEAssociatedLogicalS1ConnectionListResComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s36.UEAssociatedLogicalS1ConnectionListRes
				return zero, err
			}
			return complete.Value, nil
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldEncode(&sealed) = func(value s36.UEAssociatedLogicalS1ConnectionListRes, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := UEAssociatedLogicalS1ConnectionListResComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCapture(&sealed) = func(v s36.UEAssociatedLogicalS1ConnectionListRes, options aper.DecodeState) (s36.UEAssociatedLogicalS1ConnectionListRes, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEAssociatedLogicalS1ConnectionListRes(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldCompare(&sealed) = func(v s36.UEAssociatedLogicalS1ConnectionListRes, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEAssociatedLogicalS1ConnectionListRes(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s36.BridgeUEAssociatedLogicalS1ConnectionListResValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAssociatedLogicalS1ConnectionListRes"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEHistoryInformationCodec binds the complete source value type.
func UEHistoryInformationCodec() s41.UEHistoryInformationValueCodec {
	return func() s41.UEHistoryInformationValueCodec {
		sealed := s41.UEHistoryInformationValueCodec{}
		*s41.BridgeUEHistoryInformationValueCodecFieldPath(&sealed) = "UEHistoryInformation"
		*s41.BridgeUEHistoryInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.UEHistoryInformation, error) {
			var complete UEHistoryInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s41.UEHistoryInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*s41.BridgeUEHistoryInformationValueCodecFieldEncode(&sealed) = func(value s41.UEHistoryInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := UEHistoryInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s41.BridgeUEHistoryInformationValueCodecFieldCapture(&sealed) = func(v s41.UEHistoryInformation, options aper.DecodeState) (s41.UEHistoryInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s41.BridgeCaptureS1APUEHistoryInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeUEHistoryInformationValueCodecFieldCompare(&sealed) = func(v s41.UEHistoryInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s41.BridgeCompareS1APUEHistoryInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeUEHistoryInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEHistoryInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasConfigNameListCodec binds the complete source value type.
func WLANMeasConfigNameListCodec() s02.WLANMeasConfigNameListValueCodec {
	return func() s02.WLANMeasConfigNameListValueCodec {
		sealed := s02.WLANMeasConfigNameListValueCodec{}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldPath(&sealed) = "WLANMeasConfigNameList"
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANMeasConfigNameList, error) {
			var complete WLANMeasConfigNameListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.WLANMeasConfigNameList
				return zero, err
			}
			return complete.Value, nil
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldEncode(&sealed) = func(value s00.WLANMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := WLANMeasConfigNameListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldCapture(&sealed) = func(v s00.WLANMeasConfigNameList, options aper.DecodeState) (s00.WLANMeasConfigNameList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWLANMeasConfigNameList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldCompare(&sealed) = func(v s00.WLANMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APWLANMeasConfigNameList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWLANMeasConfigNameListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasConfigNameList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldCodec(v *ERABModificationIndicationCSGMembershipInfoIEBinding) *s14.CSGMembershipInfoValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldGet(v *ERABModificationIndicationCSGMembershipInfoIEBinding) *func(*ERABModificationIndicationIEValue) (*s14.CSGMembershipInfo, bool) {
	return &v.get
}
func BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInfo(v *ERABModificationIndicationCSGMembershipInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationCSGMembershipInfoIEBindingFieldInject(v *ERABModificationIndicationCSGMembershipInfoIEBinding) *func(s14.CSGMembershipInfo) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationENBUES1APIDIEBindingFieldCodec(v *ERABModificationIndicationENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationENBUES1APIDIEBindingFieldGet(v *ERABModificationIndicationENBUES1APIDIEBinding) *func(*ERABModificationIndicationIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInfo(v *ERABModificationIndicationENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationENBUES1APIDIEBindingFieldInject(v *ERABModificationIndicationENBUES1APIDIEBinding) *func(s00.ENBUES1APID) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldCodec(v *ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) *s16.ERABNotToBeModifiedListBearerModIndValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldGet(v *ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) *func(*ERABModificationIndicationIEValue) (*s16.ERABNotToBeModifiedListBearerModInd, bool) {
	return &v.get
}
func BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInfo(v *ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBindingFieldInject(v *ERABModificationIndicationERABNotToBeModifiedListBearerModIndIEBinding) *func(s16.ERABNotToBeModifiedListBearerModInd) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldCodec(v *ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) *s17.ERABToBeModifiedListBearerModIndValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldGet(v *ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) *func(*ERABModificationIndicationIEValue) (*s17.ERABToBeModifiedListBearerModInd, bool) {
	return &v.get
}
func BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInfo(v *ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationERABToBeModifiedListBearerModIndIEBindingFieldInject(v *ERABModificationIndicationERABToBeModifiedListBearerModIndIEBinding) *func(s17.ERABToBeModifiedListBearerModInd) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationIEContainerAPERValueFieldContext(v *ERABModificationIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEContainerAPERValueFieldReceived(v *ERABModificationIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEContainerAPERValueFieldReplay(v *ERABModificationIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEContainerAPERValueFieldWithoutReplay(v *ERABModificationIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldCapture(v *ERABModificationIndicationIEContainerValueCodec) *func(ERABModificationIndicationIEContainer, aper.DecodeState) (ERABModificationIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldCompare(v *ERABModificationIndicationIEContainerValueCodec) *func(ERABModificationIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldContext(v *ERABModificationIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldDecode(v *ERABModificationIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndicationIEContainer, error) {
	return &v.decode
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldEncode(v *ERABModificationIndicationIEContainerValueCodec) *func(ERABModificationIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationIEContainerValueCodecFieldPath(v *ERABModificationIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationIndicationIEContainerValueCodecMethodEncodeBudgetValue(v ERABModificationIndicationIEContainerValueCodec, a0 ERABModificationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationIndicationIEContainerValueCodecMethodEncodeChanged(v ERABModificationIndicationIEContainerValueCodec, a0 ERABModificationIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationIndicationIEFieldAPERValueFieldContext(v *ERABModificationIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEFieldAPERValueFieldReceived(v *ERABModificationIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEFieldAPERValueFieldReplay(v *ERABModificationIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEFieldAPERValueFieldWithoutReplay(v *ERABModificationIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEFieldFieldReceived(v *ERABModificationIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeERABModificationIndicationIEFieldFieldReplay(v *ERABModificationIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEFieldFieldStream(v *ERABModificationIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeERABModificationIndicationIEFieldFieldWithoutReplay(v *ERABModificationIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(v *ERABModificationIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeERABModificationIndicationIEFieldMethodUnmarshalAPERFrom(v *ERABModificationIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldCapture(v *ERABModificationIndicationIEFieldValueCodec) *func(ERABModificationIndicationIEField, aper.DecodeState) (ERABModificationIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldCompare(v *ERABModificationIndicationIEFieldValueCodec) *func(ERABModificationIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldContext(v *ERABModificationIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldDecode(v *ERABModificationIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndicationIEField, error) {
	return &v.decode
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldEncode(v *ERABModificationIndicationIEFieldValueCodec) *func(ERABModificationIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationIEFieldValueCodecFieldPath(v *ERABModificationIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationIndicationIEFieldValueCodecMethodEncodeBudgetValue(v ERABModificationIndicationIEFieldValueCodec, a0 ERABModificationIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationIndicationIEFieldValueCodecMethodEncodeChanged(v ERABModificationIndicationIEFieldValueCodec, a0 ERABModificationIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationIndicationIEValueERABIEContainerListAPERValueFieldContext(v *ERABModificationIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *ERABModificationIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *ERABModificationIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *func(ERABModificationIndicationIEValueERABIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *func(ERABModificationIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *func(ERABModificationIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecFieldPath(v *ERABModificationIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationIndicationIEValueERABIEContainerListValueCodec, a0 ERABModificationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ERABModificationIndicationIEValueERABIEContainerListValueCodec, a0 ERABModificationIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationIndicationIEValueFieldId(v *ERABModificationIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeERABModificationIndicationIEValueFieldIsOpaque(v *ERABModificationIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeERABModificationIndicationIEValueFieldOpaque(v *ERABModificationIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeERABModificationIndicationIEValueFieldReceived(v *ERABModificationIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEValueFieldReplay(v *ERABModificationIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEValueFieldRowCSGMembershipInfo(v *ERABModificationIndicationIEValue) **s14.CSGMembershipInfo {
	return &v.rowCSGMembershipInfo
}
func BridgeERABModificationIndicationIEValueFieldRowENBUES1APID(v *ERABModificationIndicationIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeERABModificationIndicationIEValueFieldRowERABNotToBeModifiedListBearerModInd(v *ERABModificationIndicationIEValue) **s16.ERABNotToBeModifiedListBearerModInd {
	return &v.rowERABNotToBeModifiedListBearerModInd
}
func BridgeERABModificationIndicationIEValueFieldRowERABToBeModifiedListBearerModInd(v *ERABModificationIndicationIEValue) **s17.ERABToBeModifiedListBearerModInd {
	return &v.rowERABToBeModifiedListBearerModInd
}
func BridgeERABModificationIndicationIEValueFieldRowMMEUES1APID(v *ERABModificationIndicationIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeERABModificationIndicationIEValueFieldRowSecondaryRATDataUsageReportList(v *ERABModificationIndicationIEValue) **s28.SecondaryRATDataUsageReportList {
	return &v.rowSecondaryRATDataUsageReportList
}
func BridgeERABModificationIndicationIEValueFieldRowTunnelInformationForBBF(v *ERABModificationIndicationIEValue) **s35.TunnelInformation {
	return &v.rowTunnelInformationForBBF
}
func BridgeERABModificationIndicationIEValueFieldRowUserLocationInformation(v *ERABModificationIndicationIEValue) **UserLocationInformation {
	return &v.rowUserLocationInformation
}
func BridgeERABModificationIndicationIEValueMethodCaptureSemantics(v ERABModificationIndicationIEValue, a0 aper.SemanticCapture) ERABModificationIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeERABModificationIndicationIEValueMethodCompareSemantics(v ERABModificationIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeERABModificationIndicationIEValueMethodDecode(v ERABModificationIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ERABModificationIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeERABModificationIndicationIEValueMethodEncode(v ERABModificationIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeERABModificationIndicationIEValueMethodEncodeFresh(v ERABModificationIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeERABModificationIndicationIEValueMethodMatchesID(v ERABModificationIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeERABModificationIndicationIEValueMethodReason(v ERABModificationIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeERABModificationIndicationIEValueMethodRule(v ERABModificationIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModificationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ERABModificationIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 ERABModificationIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ERABModificationIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolIEContainerList, aper.DecodeState) (ERABModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ERABModificationIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *func(ERABModificationIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *ERABModificationIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ERABModificationIndicationIEValueProtocolIEContainerListValueCodec, a0 ERABModificationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeERABModificationIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ERABModificationIndicationIEValueProtocolIEContainerListValueCodec, a0 ERABModificationIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldCodec(v *ERABModificationIndicationMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldGet(v *ERABModificationIndicationMMEUES1APIDIEBinding) *func(*ERABModificationIndicationIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInfo(v *ERABModificationIndicationMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationMMEUES1APIDIEBindingFieldInject(v *ERABModificationIndicationMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldCodec(v *ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) *s28.SecondaryRATDataUsageReportListValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldGet(v *ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) *func(*ERABModificationIndicationIEValue) (*s28.SecondaryRATDataUsageReportList, bool) {
	return &v.get
}
func BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInfo(v *ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationSecondaryRATDataUsageReportListIEBindingFieldInject(v *ERABModificationIndicationSecondaryRATDataUsageReportListIEBinding) *func(s28.SecondaryRATDataUsageReportList) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgeERABModificationIndicationTunnelInformationIEBindingFieldCodec(v *ERABModificationIndicationTunnelInformationIEBinding) *s35.TunnelInformationValueCodec {
	return &v.codec
}
func BridgeERABModificationIndicationTunnelInformationIEBindingFieldGet(v *ERABModificationIndicationTunnelInformationIEBinding) *func(*ERABModificationIndicationIEValue) (*s35.TunnelInformation, bool) {
	return &v.get
}
func BridgeERABModificationIndicationTunnelInformationIEBindingFieldInfo(v *ERABModificationIndicationTunnelInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeERABModificationIndicationTunnelInformationIEBindingFieldInject(v *ERABModificationIndicationTunnelInformationIEBinding) *func(s35.TunnelInformation) ERABModificationIndicationIEValue {
	return &v.inject
}
func BridgePWSRestartIndicationAPERValueFieldContext(v *PWSRestartIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationAPERValueFieldReceived(v *PWSRestartIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationAPERValueFieldReplay(v *PWSRestartIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationAPERValueFieldWithoutReplay(v *PWSRestartIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationECGIListForRestartIEBindingFieldCodec(v *PWSRestartIndicationECGIListForRestartIEBinding) *s17.ECGIListForRestartValueCodec {
	return &v.codec
}
func BridgePWSRestartIndicationECGIListForRestartIEBindingFieldGet(v *PWSRestartIndicationECGIListForRestartIEBinding) *func(*PWSRestartIndicationIEValue) (*s17.ECGIListForRestart, bool) {
	return &v.get
}
func BridgePWSRestartIndicationECGIListForRestartIEBindingFieldInfo(v *PWSRestartIndicationECGIListForRestartIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSRestartIndicationECGIListForRestartIEBindingFieldInject(v *PWSRestartIndicationECGIListForRestartIEBinding) *func(s17.ECGIListForRestart) PWSRestartIndicationIEValue {
	return &v.inject
}
func BridgePWSRestartIndicationEmergencyAreaIDListForRestartIEBindingFieldCodec(v *PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) *s00.EmergencyAreaIDListForRestartValueCodec {
	return &v.codec
}
func BridgePWSRestartIndicationEmergencyAreaIDListForRestartIEBindingFieldGet(v *PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) *func(*PWSRestartIndicationIEValue) (*s00.EmergencyAreaIDListForRestart, bool) {
	return &v.get
}
func BridgePWSRestartIndicationEmergencyAreaIDListForRestartIEBindingFieldInfo(v *PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSRestartIndicationEmergencyAreaIDListForRestartIEBindingFieldInject(v *PWSRestartIndicationEmergencyAreaIDListForRestartIEBinding) *func(s00.EmergencyAreaIDListForRestart) PWSRestartIndicationIEValue {
	return &v.inject
}
func BridgePWSRestartIndicationFieldExtCount(v *PWSRestartIndication) *int64   { return &v.extCount }
func BridgePWSRestartIndicationFieldExtData(v *PWSRestartIndication) *[][]byte { return &v.extData }
func BridgePWSRestartIndicationFieldExtOrigin(v *PWSRestartIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePWSRestartIndicationFieldExtPresent(v *PWSRestartIndication) *[]bool { return &v.extPresent }
func BridgePWSRestartIndicationFieldExtWire(v *PWSRestartIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePWSRestartIndicationFieldPerExtPadding(v *PWSRestartIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePWSRestartIndicationFieldPerPadding(v *PWSRestartIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePWSRestartIndicationFieldProtocolIEsIndef(v *PWSRestartIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgePWSRestartIndicationFieldReceived(v *PWSRestartIndication) *bool { return &v.received }
func BridgePWSRestartIndicationFieldReceivedAbsolute(v *PWSRestartIndication) *bool {
	return &v.receivedAbsolute
}
func BridgePWSRestartIndicationFieldReceivedBytes(v *PWSRestartIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePWSRestartIndicationFieldReceivedLocation(v *PWSRestartIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgePWSRestartIndicationFieldReplay(v *PWSRestartIndication) *aper.Snapshot { return &v.replay }
func BridgePWSRestartIndicationFieldStream(v *PWSRestartIndication) *aper.WireSpan { return &v.stream }
func BridgePWSRestartIndicationFieldWithoutReplay(v *PWSRestartIndication) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationGlobalENBIDIEBindingFieldCodec(v *PWSRestartIndicationGlobalENBIDIEBinding) *s18.GlobalENBIDValueCodec {
	return &v.codec
}
func BridgePWSRestartIndicationGlobalENBIDIEBindingFieldGet(v *PWSRestartIndicationGlobalENBIDIEBinding) *func(*PWSRestartIndicationIEValue) (*s18.GlobalENBID, bool) {
	return &v.get
}
func BridgePWSRestartIndicationGlobalENBIDIEBindingFieldInfo(v *PWSRestartIndicationGlobalENBIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSRestartIndicationGlobalENBIDIEBindingFieldInject(v *PWSRestartIndicationGlobalENBIDIEBinding) *func(s18.GlobalENBID) PWSRestartIndicationIEValue {
	return &v.inject
}
func BridgePWSRestartIndicationIEContainerAPERValueFieldContext(v *PWSRestartIndicationIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEContainerAPERValueFieldReceived(v *PWSRestartIndicationIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEContainerAPERValueFieldReplay(v *PWSRestartIndicationIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEContainerAPERValueFieldWithoutReplay(v *PWSRestartIndicationIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldCapture(v *PWSRestartIndicationIEContainerValueCodec) *func(PWSRestartIndicationIEContainer, aper.DecodeState) (PWSRestartIndicationIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldCompare(v *PWSRestartIndicationIEContainerValueCodec) *func(PWSRestartIndicationIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldContext(v *PWSRestartIndicationIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldDecode(v *PWSRestartIndicationIEContainerValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndicationIEContainer, error) {
	return &v.decode
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldEncode(v *PWSRestartIndicationIEContainerValueCodec) *func(PWSRestartIndicationIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationIEContainerValueCodecFieldPath(v *PWSRestartIndicationIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationIEContainerValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationIEContainerValueCodec, a0 PWSRestartIndicationIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationIEContainerValueCodecMethodEncodeChanged(v PWSRestartIndicationIEContainerValueCodec, a0 PWSRestartIndicationIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSRestartIndicationIEFieldAPERValueFieldContext(v *PWSRestartIndicationIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEFieldAPERValueFieldReceived(v *PWSRestartIndicationIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEFieldAPERValueFieldReplay(v *PWSRestartIndicationIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEFieldAPERValueFieldWithoutReplay(v *PWSRestartIndicationIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEFieldFieldReceived(v *PWSRestartIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePWSRestartIndicationIEFieldFieldReplay(v *PWSRestartIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEFieldFieldStream(v *PWSRestartIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePWSRestartIndicationIEFieldFieldWithoutReplay(v *PWSRestartIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEFieldMethodMarshalAPERTo(v *PWSRestartIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePWSRestartIndicationIEFieldMethodUnmarshalAPERFrom(v *PWSRestartIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldCapture(v *PWSRestartIndicationIEFieldValueCodec) *func(PWSRestartIndicationIEField, aper.DecodeState) (PWSRestartIndicationIEField, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldCompare(v *PWSRestartIndicationIEFieldValueCodec) *func(PWSRestartIndicationIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldContext(v *PWSRestartIndicationIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldDecode(v *PWSRestartIndicationIEFieldValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndicationIEField, error) {
	return &v.decode
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldEncode(v *PWSRestartIndicationIEFieldValueCodec) *func(PWSRestartIndicationIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationIEFieldValueCodecFieldPath(v *PWSRestartIndicationIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationIEFieldValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationIEFieldValueCodec, a0 PWSRestartIndicationIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationIEFieldValueCodecMethodEncodeChanged(v PWSRestartIndicationIEFieldValueCodec, a0 PWSRestartIndicationIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSRestartIndicationIETableMethodInfoECGIListForRestart(v PWSRestartIndicationIETable) s00.FieldInfo {
	return v.infoECGIListForRestart()
}
func BridgePWSRestartIndicationIETableMethodInfoEmergencyAreaIDListForRestart(v PWSRestartIndicationIETable) s00.FieldInfo {
	return v.infoEmergencyAreaIDListForRestart()
}
func BridgePWSRestartIndicationIETableMethodInfoGlobalENBID(v PWSRestartIndicationIETable) s00.FieldInfo {
	return v.infoGlobalENBID()
}
func BridgePWSRestartIndicationIETableMethodInfoTAIListForRestart(v PWSRestartIndicationIETable) s00.FieldInfo {
	return v.infoTAIListForRestart()
}
func BridgePWSRestartIndicationIEValueERABIEContainerListAPERValueFieldContext(v *PWSRestartIndicationIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueERABIEContainerListAPERValueFieldReceived(v *PWSRestartIndicationIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEValueERABIEContainerListAPERValueFieldReplay(v *PWSRestartIndicationIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *PWSRestartIndicationIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldCapture(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *func(PWSRestartIndicationIEValueERABIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldCompare(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *func(PWSRestartIndicationIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldContext(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldDecode(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldEncode(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *func(PWSRestartIndicationIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecFieldPath(v *PWSRestartIndicationIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationIEValueERABIEContainerListValueCodec, a0 PWSRestartIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationIEValueERABIEContainerListValueCodecMethodEncodeChanged(v PWSRestartIndicationIEValueERABIEContainerListValueCodec, a0 PWSRestartIndicationIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSRestartIndicationIEValueFieldId(v *PWSRestartIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePWSRestartIndicationIEValueFieldIsOpaque(v *PWSRestartIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgePWSRestartIndicationIEValueFieldOpaque(v *PWSRestartIndicationIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePWSRestartIndicationIEValueFieldReceived(v *PWSRestartIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEValueFieldReplay(v *PWSRestartIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEValueFieldRowECGIListForRestart(v *PWSRestartIndicationIEValue) **s17.ECGIListForRestart {
	return &v.rowECGIListForRestart
}
func BridgePWSRestartIndicationIEValueFieldRowEmergencyAreaIDListForRestart(v *PWSRestartIndicationIEValue) **s00.EmergencyAreaIDListForRestart {
	return &v.rowEmergencyAreaIDListForRestart
}
func BridgePWSRestartIndicationIEValueFieldRowGlobalENBID(v *PWSRestartIndicationIEValue) **s18.GlobalENBID {
	return &v.rowGlobalENBID
}
func BridgePWSRestartIndicationIEValueFieldRowTAIListForRestart(v *PWSRestartIndicationIEValue) **s32.TAIListForRestart {
	return &v.rowTAIListForRestart
}
func BridgePWSRestartIndicationIEValueMethodCaptureSemantics(v PWSRestartIndicationIEValue, a0 aper.SemanticCapture) PWSRestartIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgePWSRestartIndicationIEValueMethodCompareSemantics(v PWSRestartIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePWSRestartIndicationIEValueMethodDecode(v PWSRestartIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PWSRestartIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgePWSRestartIndicationIEValueMethodEncode(v PWSRestartIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgePWSRestartIndicationIEValueMethodEncodeFresh(v PWSRestartIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePWSRestartIndicationIEValueMethodMatchesID(v PWSRestartIndicationIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgePWSRestartIndicationIEValueMethodReason(v PWSRestartIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePWSRestartIndicationIEValueMethodRule(v PWSRestartIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 PWSRestartIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v PWSRestartIndicationIEValueProtocolErrorIEContainerListValueCodec, a0 PWSRestartIndicationIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListAPERValueFieldContext(v *PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListAPERValueFieldReceived(v *PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListAPERValueFieldReplay(v *PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *PWSRestartIndicationIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolIEContainerList, aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldContext(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndicationIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *func(PWSRestartIndicationIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecFieldPath(v *PWSRestartIndicationIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationIEValueProtocolIEContainerListValueCodec, a0 PWSRestartIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v PWSRestartIndicationIEValueProtocolIEContainerListValueCodec, a0 PWSRestartIndicationIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePWSRestartIndicationMethodMarshalAPERBudget(v *PWSRestartIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePWSRestartIndicationMethodMarshalAPERBudgetValue(v *PWSRestartIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgePWSRestartIndicationMethodMarshalAPERChanged(v *PWSRestartIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePWSRestartIndicationMethodMarshalAPERChangedValue(v *PWSRestartIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePWSRestartIndicationMethodMarshalAPERLegacy(v *PWSRestartIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePWSRestartIndicationMethodMarshalAPERNewValue(v *PWSRestartIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgePWSRestartIndicationMethodMarshalAPERPlanned(v *PWSRestartIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgePWSRestartIndicationMethodMarshalAPERTo(v *PWSRestartIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePWSRestartIndicationMethodUnmarshalAPERFrom(v *PWSRestartIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePWSRestartIndicationMethodUnmarshalAPERLegacy(v *PWSRestartIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePWSRestartIndicationMethodUnmarshalAPERWithOptions(v *PWSRestartIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePWSRestartIndicationTAIListForRestartIEBindingFieldCodec(v *PWSRestartIndicationTAIListForRestartIEBinding) *s32.TAIListForRestartValueCodec {
	return &v.codec
}
func BridgePWSRestartIndicationTAIListForRestartIEBindingFieldGet(v *PWSRestartIndicationTAIListForRestartIEBinding) *func(*PWSRestartIndicationIEValue) (*s32.TAIListForRestart, bool) {
	return &v.get
}
func BridgePWSRestartIndicationTAIListForRestartIEBindingFieldInfo(v *PWSRestartIndicationTAIListForRestartIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgePWSRestartIndicationTAIListForRestartIEBindingFieldInject(v *PWSRestartIndicationTAIListForRestartIEBinding) *func(s32.TAIListForRestart) PWSRestartIndicationIEValue {
	return &v.inject
}
func BridgePWSRestartIndicationValueCodecFieldCapture(v *PWSRestartIndicationValueCodec) *func(PWSRestartIndication, aper.DecodeState) (PWSRestartIndication, aper.Snapshot) {
	return &v.capture
}
func BridgePWSRestartIndicationValueCodecFieldCompare(v *PWSRestartIndicationValueCodec) *func(PWSRestartIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePWSRestartIndicationValueCodecFieldContext(v *PWSRestartIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePWSRestartIndicationValueCodecFieldDecode(v *PWSRestartIndicationValueCodec) *func([]byte, aper.DecodeState) (PWSRestartIndication, error) {
	return &v.decode
}
func BridgePWSRestartIndicationValueCodecFieldEncode(v *PWSRestartIndicationValueCodec) *func(PWSRestartIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePWSRestartIndicationValueCodecFieldPath(v *PWSRestartIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgePWSRestartIndicationValueCodecMethodEncodeBudgetValue(v PWSRestartIndicationValueCodec, a0 PWSRestartIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgePWSRestartIndicationValueCodecMethodEncodeChanged(v PWSRestartIndicationValueCodec, a0 PWSRestartIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeAPERValueFieldContext(v *ResetAcknowledgeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeAPERValueFieldReceived(v *ResetAcknowledgeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeAPERValueFieldReplay(v *ResetAcknowledgeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeAPERValueFieldWithoutReplay(v *ResetAcknowledgeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeCriticalityDiagnosticsIEBindingFieldCodec(v *ResetAcknowledgeCriticalityDiagnosticsIEBinding) *s22.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeResetAcknowledgeCriticalityDiagnosticsIEBindingFieldGet(v *ResetAcknowledgeCriticalityDiagnosticsIEBinding) *func(*ResetAcknowledgeIEValue) (*s22.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeResetAcknowledgeCriticalityDiagnosticsIEBindingFieldInfo(v *ResetAcknowledgeCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResetAcknowledgeCriticalityDiagnosticsIEBindingFieldInject(v *ResetAcknowledgeCriticalityDiagnosticsIEBinding) *func(s22.CriticalityDiagnostics) ResetAcknowledgeIEValue {
	return &v.inject
}
func BridgeResetAcknowledgeFieldExtCount(v *ResetAcknowledge) *int64   { return &v.extCount }
func BridgeResetAcknowledgeFieldExtData(v *ResetAcknowledge) *[][]byte { return &v.extData }
func BridgeResetAcknowledgeFieldExtOrigin(v *ResetAcknowledge) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeResetAcknowledgeFieldExtPresent(v *ResetAcknowledge) *[]bool       { return &v.extPresent }
func BridgeResetAcknowledgeFieldExtWire(v *ResetAcknowledge) *[]aper.WireSpan { return &v.extWire }
func BridgeResetAcknowledgeFieldPerExtPadding(v *ResetAcknowledge) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResetAcknowledgeFieldPerPadding(v *ResetAcknowledge) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeResetAcknowledgeFieldProtocolIEsIndef(v *ResetAcknowledge) *bool {
	return &v.protocolIEsIndef
}
func BridgeResetAcknowledgeFieldReceived(v *ResetAcknowledge) *bool { return &v.received }
func BridgeResetAcknowledgeFieldReceivedAbsolute(v *ResetAcknowledge) *bool {
	return &v.receivedAbsolute
}
func BridgeResetAcknowledgeFieldReceivedBytes(v *ResetAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResetAcknowledgeFieldReceivedLocation(v *ResetAcknowledge) *aper.Location {
	return &v.receivedLocation
}
func BridgeResetAcknowledgeFieldReplay(v *ResetAcknowledge) *aper.Snapshot { return &v.replay }
func BridgeResetAcknowledgeFieldStream(v *ResetAcknowledge) *aper.WireSpan { return &v.stream }
func BridgeResetAcknowledgeFieldWithoutReplay(v *ResetAcknowledge) *bool   { return &v.withoutReplay }
func BridgeResetAcknowledgeIEContainerAPERValueFieldContext(v *ResetAcknowledgeIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEContainerAPERValueFieldReceived(v *ResetAcknowledgeIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEContainerAPERValueFieldReplay(v *ResetAcknowledgeIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEContainerAPERValueFieldWithoutReplay(v *ResetAcknowledgeIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldCapture(v *ResetAcknowledgeIEContainerValueCodec) *func(ResetAcknowledgeIEContainer, aper.DecodeState) (ResetAcknowledgeIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldCompare(v *ResetAcknowledgeIEContainerValueCodec) *func(ResetAcknowledgeIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldContext(v *ResetAcknowledgeIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldDecode(v *ResetAcknowledgeIEContainerValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledgeIEContainer, error) {
	return &v.decode
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldEncode(v *ResetAcknowledgeIEContainerValueCodec) *func(ResetAcknowledgeIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeIEContainerValueCodecFieldPath(v *ResetAcknowledgeIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeIEContainerValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeIEContainerValueCodec, a0 ResetAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeIEContainerValueCodecMethodEncodeChanged(v ResetAcknowledgeIEContainerValueCodec, a0 ResetAcknowledgeIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeIEFieldAPERValueFieldContext(v *ResetAcknowledgeIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEFieldAPERValueFieldReceived(v *ResetAcknowledgeIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEFieldAPERValueFieldReplay(v *ResetAcknowledgeIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEFieldAPERValueFieldWithoutReplay(v *ResetAcknowledgeIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEFieldFieldReceived(v *ResetAcknowledgeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResetAcknowledgeIEFieldFieldReplay(v *ResetAcknowledgeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEFieldFieldStream(v *ResetAcknowledgeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResetAcknowledgeIEFieldFieldWithoutReplay(v *ResetAcknowledgeIEField) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEFieldMethodMarshalAPERTo(v *ResetAcknowledgeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetAcknowledgeIEFieldMethodUnmarshalAPERFrom(v *ResetAcknowledgeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldCapture(v *ResetAcknowledgeIEFieldValueCodec) *func(ResetAcknowledgeIEField, aper.DecodeState) (ResetAcknowledgeIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldCompare(v *ResetAcknowledgeIEFieldValueCodec) *func(ResetAcknowledgeIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldContext(v *ResetAcknowledgeIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldDecode(v *ResetAcknowledgeIEFieldValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledgeIEField, error) {
	return &v.decode
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldEncode(v *ResetAcknowledgeIEFieldValueCodec) *func(ResetAcknowledgeIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeIEFieldValueCodecFieldPath(v *ResetAcknowledgeIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeIEFieldValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeIEFieldValueCodec, a0 ResetAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeIEFieldValueCodecMethodEncodeChanged(v ResetAcknowledgeIEFieldValueCodec, a0 ResetAcknowledgeIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeIETableMethodInfoCriticalityDiagnostics(v ResetAcknowledgeIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeResetAcknowledgeIETableMethodInfoUEAssociatedLogicalS1ConnectionListResAck(v ResetAcknowledgeIETable) s00.FieldInfo {
	return v.infoUEAssociatedLogicalS1ConnectionListResAck()
}
func BridgeResetAcknowledgeIEValueERABIEContainerListAPERValueFieldContext(v *ResetAcknowledgeIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueERABIEContainerListAPERValueFieldReceived(v *ResetAcknowledgeIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEValueERABIEContainerListAPERValueFieldReplay(v *ResetAcknowledgeIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ResetAcknowledgeIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldCapture(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *func(ResetAcknowledgeIEValueERABIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldCompare(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *func(ResetAcknowledgeIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldContext(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldDecode(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldEncode(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *func(ResetAcknowledgeIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecFieldPath(v *ResetAcknowledgeIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeIEValueERABIEContainerListValueCodec, a0 ResetAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ResetAcknowledgeIEValueERABIEContainerListValueCodec, a0 ResetAcknowledgeIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeIEValueFieldId(v *ResetAcknowledgeIEValue) *s00.ProtocolIEID { return &v.id }
func BridgeResetAcknowledgeIEValueFieldIsOpaque(v *ResetAcknowledgeIEValue) *bool       { return &v.isOpaque }
func BridgeResetAcknowledgeIEValueFieldOpaque(v *ResetAcknowledgeIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResetAcknowledgeIEValueFieldReceived(v *ResetAcknowledgeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEValueFieldReplay(v *ResetAcknowledgeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEValueFieldRowCriticalityDiagnostics(v *ResetAcknowledgeIEValue) **s22.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeResetAcknowledgeIEValueFieldRowUEAssociatedLogicalS1ConnectionListResAck(v *ResetAcknowledgeIEValue) **s36.UEAssociatedLogicalS1ConnectionListResAck {
	return &v.rowUEAssociatedLogicalS1ConnectionListResAck
}
func BridgeResetAcknowledgeIEValueMethodCaptureSemantics(v ResetAcknowledgeIEValue, a0 aper.SemanticCapture) ResetAcknowledgeIEValue {
	return v.captureSemantics(a0)
}
func BridgeResetAcknowledgeIEValueMethodCompareSemantics(v ResetAcknowledgeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResetAcknowledgeIEValueMethodDecode(v ResetAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResetAcknowledgeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeResetAcknowledgeIEValueMethodEncode(v ResetAcknowledgeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeResetAcknowledgeIEValueMethodEncodeFresh(v ResetAcknowledgeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResetAcknowledgeIEValueMethodMatchesID(v ResetAcknowledgeIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeResetAcknowledgeIEValueMethodReason(v ResetAcknowledgeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResetAcknowledgeIEValueMethodRule(v ResetAcknowledgeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 ResetAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ResetAcknowledgeIEValueProtocolErrorIEContainerListValueCodec, a0 ResetAcknowledgeIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListAPERValueFieldContext(v *ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReceived(v *ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListAPERValueFieldReplay(v *ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ResetAcknowledgeIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCapture(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldCompare(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldContext(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldDecode(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledgeIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldEncode(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *func(ResetAcknowledgeIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecFieldPath(v *ResetAcknowledgeIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 ResetAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ResetAcknowledgeIEValueProtocolIEContainerListValueCodec, a0 ResetAcknowledgeIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetAcknowledgeMethodMarshalAPERBudget(v *ResetAcknowledge, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResetAcknowledgeMethodMarshalAPERBudgetValue(v *ResetAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeResetAcknowledgeMethodMarshalAPERChanged(v *ResetAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResetAcknowledgeMethodMarshalAPERChangedValue(v *ResetAcknowledge, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResetAcknowledgeMethodMarshalAPERLegacy(v *ResetAcknowledge) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResetAcknowledgeMethodMarshalAPERNewValue(v *ResetAcknowledge, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeResetAcknowledgeMethodMarshalAPERPlanned(v *ResetAcknowledge, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeResetAcknowledgeMethodMarshalAPERTo(v *ResetAcknowledge, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetAcknowledgeMethodUnmarshalAPERFrom(v *ResetAcknowledge, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetAcknowledgeMethodUnmarshalAPERLegacy(v *ResetAcknowledge, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResetAcknowledgeMethodUnmarshalAPERWithOptions(v *ResetAcknowledge, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBindingFieldCodec(v *ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) *s36.UEAssociatedLogicalS1ConnectionListResAckValueCodec {
	return &v.codec
}
func BridgeResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBindingFieldGet(v *ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) *func(*ResetAcknowledgeIEValue) (*s36.UEAssociatedLogicalS1ConnectionListResAck, bool) {
	return &v.get
}
func BridgeResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBindingFieldInfo(v *ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBindingFieldInject(v *ResetAcknowledgeUEAssociatedLogicalS1ConnectionListResAckIEBinding) *func(s36.UEAssociatedLogicalS1ConnectionListResAck) ResetAcknowledgeIEValue {
	return &v.inject
}
func BridgeResetAcknowledgeValueCodecFieldCapture(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, aper.DecodeState) (ResetAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeValueCodecFieldCompare(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeValueCodecFieldContext(v *ResetAcknowledgeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeValueCodecFieldDecode(v *ResetAcknowledgeValueCodec) *func([]byte, aper.DecodeState) (ResetAcknowledge, error) {
	return &v.decode
}
func BridgeResetAcknowledgeValueCodecFieldEncode(v *ResetAcknowledgeValueCodec) *func(ResetAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeValueCodecFieldPath(v *ResetAcknowledgeValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAcknowledgeValueCodecMethodEncodeBudgetValue(v ResetAcknowledgeValueCodec, a0 ResetAcknowledge, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetAcknowledgeValueCodecMethodEncodeChanged(v ResetAcknowledgeValueCodec, a0 ResetAcknowledge, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1SetupRequestAPERValueFieldContext(v *S1SetupRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestAPERValueFieldReceived(v *S1SetupRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeS1SetupRequestAPERValueFieldReplay(v *S1SetupRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeS1SetupRequestAPERValueFieldWithoutReplay(v *S1SetupRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeS1SetupRequestFieldExtCount(v *S1SetupRequest) *int64                { return &v.extCount }
func BridgeS1SetupRequestFieldExtData(v *S1SetupRequest) *[][]byte              { return &v.extData }
func BridgeS1SetupRequestFieldExtOrigin(v *S1SetupRequest) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeS1SetupRequestFieldExtPresent(v *S1SetupRequest) *[]bool             { return &v.extPresent }
func BridgeS1SetupRequestFieldExtWire(v *S1SetupRequest) *[]aper.WireSpan       { return &v.extWire }
func BridgeS1SetupRequestFieldPerExtPadding(v *S1SetupRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeS1SetupRequestFieldPerPadding(v *S1SetupRequest) *aper.FinalPadding { return &v.perPadding }
func BridgeS1SetupRequestFieldProtocolIEsIndef(v *S1SetupRequest) *bool        { return &v.protocolIEsIndef }
func BridgeS1SetupRequestFieldReceived(v *S1SetupRequest) *bool                { return &v.received }
func BridgeS1SetupRequestFieldReceivedAbsolute(v *S1SetupRequest) *bool        { return &v.receivedAbsolute }
func BridgeS1SetupRequestFieldReceivedBytes(v *S1SetupRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeS1SetupRequestFieldReceivedLocation(v *S1SetupRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeS1SetupRequestFieldReplay(v *S1SetupRequest) *aper.Snapshot { return &v.replay }
func BridgeS1SetupRequestFieldStream(v *S1SetupRequest) *aper.WireSpan { return &v.stream }
func BridgeS1SetupRequestFieldWithoutReplay(v *S1SetupRequest) *bool   { return &v.withoutReplay }
func BridgeS1SetupRequestMethodMarshalAPERBudget(v *S1SetupRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeS1SetupRequestMethodMarshalAPERBudgetValue(v *S1SetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeS1SetupRequestMethodMarshalAPERChanged(v *S1SetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeS1SetupRequestMethodMarshalAPERChangedValue(v *S1SetupRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeS1SetupRequestMethodMarshalAPERLegacy(v *S1SetupRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeS1SetupRequestMethodMarshalAPERNewValue(v *S1SetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeS1SetupRequestMethodMarshalAPERPlanned(v *S1SetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeS1SetupRequestMethodMarshalAPERTo(v *S1SetupRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeS1SetupRequestMethodUnmarshalAPERFrom(v *S1SetupRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeS1SetupRequestMethodUnmarshalAPERLegacy(v *S1SetupRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeS1SetupRequestMethodUnmarshalAPERWithOptions(v *S1SetupRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeS1SetupRequestValueCodecFieldCapture(v *S1SetupRequestValueCodec) *func(S1SetupRequest, aper.DecodeState) (S1SetupRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupRequestValueCodecFieldCompare(v *S1SetupRequestValueCodec) *func(S1SetupRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupRequestValueCodecFieldContext(v *S1SetupRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupRequestValueCodecFieldDecode(v *S1SetupRequestValueCodec) *func([]byte, aper.DecodeState) (S1SetupRequest, error) {
	return &v.decode
}
func BridgeS1SetupRequestValueCodecFieldEncode(v *S1SetupRequestValueCodec) *func(S1SetupRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupRequestValueCodecFieldPath(v *S1SetupRequestValueCodec) *aper.Path { return &v.path }
func BridgeS1SetupRequestValueCodecMethodEncodeBudgetValue(v S1SetupRequestValueCodec, a0 S1SetupRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeS1SetupRequestValueCodecMethodEncodeChanged(v S1SetupRequestValueCodec, a0 S1SetupRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTACListInLTENTNCompleteFieldPerPadding(v *TACListInLTENTNComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTACListInLTENTNCompleteFieldReceived(v *TACListInLTENTNComplete) *bool { return &v.received }
func BridgeTACListInLTENTNCompleteFieldReceivedAbsolute(v *TACListInLTENTNComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTACListInLTENTNCompleteFieldReceivedBytes(v *TACListInLTENTNComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTACListInLTENTNCompleteFieldReceivedLocation(v *TACListInLTENTNComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTACListInLTENTNCompleteFieldReplay(v *TACListInLTENTNComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeTACListInLTENTNCompleteFieldStream(v *TACListInLTENTNComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeTACListInLTENTNCompleteFieldWithoutReplay(v *TACListInLTENTNComplete) *bool {
	return &v.withoutReplay
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERBudget(v *TACListInLTENTNComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERBudgetValue(v *TACListInLTENTNComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERChanged(v *TACListInLTENTNComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERChangedValue(v *TACListInLTENTNComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERLegacy(v *TACListInLTENTNComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERNewValue(v *TACListInLTENTNComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTACListInLTENTNCompleteMethodMarshalAPERPlanned(v *TACListInLTENTNComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTACListInLTENTNCompleteMethodUnmarshalAPERLegacy(v *TACListInLTENTNComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTACListInLTENTNCompleteMethodUnmarshalAPERWithOptions(v *TACListInLTENTNComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIBroadcastCompleteFieldPerPadding(v *TAIBroadcastComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIBroadcastCompleteFieldReceived(v *TAIBroadcastComplete) *bool { return &v.received }
func BridgeTAIBroadcastCompleteFieldReceivedAbsolute(v *TAIBroadcastComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAIBroadcastCompleteFieldReceivedBytes(v *TAIBroadcastComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIBroadcastCompleteFieldReceivedLocation(v *TAIBroadcastComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIBroadcastCompleteFieldReplay(v *TAIBroadcastComplete) *aper.Snapshot { return &v.replay }
func BridgeTAIBroadcastCompleteFieldStream(v *TAIBroadcastComplete) *aper.WireSpan { return &v.stream }
func BridgeTAIBroadcastCompleteFieldWithoutReplay(v *TAIBroadcastComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERBudget(v *TAIBroadcastComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERBudgetValue(v *TAIBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERChanged(v *TAIBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERChangedValue(v *TAIBroadcastComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERLegacy(v *TAIBroadcastComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERNewValue(v *TAIBroadcastComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIBroadcastCompleteMethodMarshalAPERPlanned(v *TAIBroadcastComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIBroadcastCompleteMethodUnmarshalAPERLegacy(v *TAIBroadcastComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIBroadcastCompleteMethodUnmarshalAPERWithOptions(v *TAIBroadcastComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAICancelledCompleteFieldPerPadding(v *TAICancelledComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAICancelledCompleteFieldReceived(v *TAICancelledComplete) *bool { return &v.received }
func BridgeTAICancelledCompleteFieldReceivedAbsolute(v *TAICancelledComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAICancelledCompleteFieldReceivedBytes(v *TAICancelledComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAICancelledCompleteFieldReceivedLocation(v *TAICancelledComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAICancelledCompleteFieldReplay(v *TAICancelledComplete) *aper.Snapshot { return &v.replay }
func BridgeTAICancelledCompleteFieldStream(v *TAICancelledComplete) *aper.WireSpan { return &v.stream }
func BridgeTAICancelledCompleteFieldWithoutReplay(v *TAICancelledComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAICancelledCompleteMethodMarshalAPERBudget(v *TAICancelledComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAICancelledCompleteMethodMarshalAPERBudgetValue(v *TAICancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAICancelledCompleteMethodMarshalAPERChanged(v *TAICancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAICancelledCompleteMethodMarshalAPERChangedValue(v *TAICancelledComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAICancelledCompleteMethodMarshalAPERLegacy(v *TAICancelledComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAICancelledCompleteMethodMarshalAPERNewValue(v *TAICancelledComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAICancelledCompleteMethodMarshalAPERPlanned(v *TAICancelledComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAICancelledCompleteMethodUnmarshalAPERLegacy(v *TAICancelledComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAICancelledCompleteMethodUnmarshalAPERWithOptions(v *TAICancelledComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIListCompleteFieldPerPadding(v *TAIListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIListCompleteFieldReceived(v *TAIListComplete) *bool         { return &v.received }
func BridgeTAIListCompleteFieldReceivedAbsolute(v *TAIListComplete) *bool { return &v.receivedAbsolute }
func BridgeTAIListCompleteFieldReceivedBytes(v *TAIListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIListCompleteFieldReceivedLocation(v *TAIListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIListCompleteFieldReplay(v *TAIListComplete) *aper.Snapshot { return &v.replay }
func BridgeTAIListCompleteFieldStream(v *TAIListComplete) *aper.WireSpan { return &v.stream }
func BridgeTAIListCompleteFieldWithoutReplay(v *TAIListComplete) *bool   { return &v.withoutReplay }
func BridgeTAIListCompleteMethodMarshalAPERBudget(v *TAIListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIListCompleteMethodMarshalAPERBudgetValue(v *TAIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIListCompleteMethodMarshalAPERChanged(v *TAIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIListCompleteMethodMarshalAPERChangedValue(v *TAIListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIListCompleteMethodMarshalAPERLegacy(v *TAIListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIListCompleteMethodMarshalAPERNewValue(v *TAIListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIListCompleteMethodMarshalAPERPlanned(v *TAIListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIListCompleteMethodUnmarshalAPERLegacy(v *TAIListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIListCompleteMethodUnmarshalAPERWithOptions(v *TAIListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIListForRestartCompleteFieldPerPadding(v *TAIListForRestartComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIListForRestartCompleteFieldReceived(v *TAIListForRestartComplete) *bool {
	return &v.received
}
func BridgeTAIListForRestartCompleteFieldReceivedAbsolute(v *TAIListForRestartComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAIListForRestartCompleteFieldReceivedBytes(v *TAIListForRestartComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIListForRestartCompleteFieldReceivedLocation(v *TAIListForRestartComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIListForRestartCompleteFieldReplay(v *TAIListForRestartComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIListForRestartCompleteFieldStream(v *TAIListForRestartComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeTAIListForRestartCompleteFieldWithoutReplay(v *TAIListForRestartComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERBudget(v *TAIListForRestartComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERBudgetValue(v *TAIListForRestartComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERChanged(v *TAIListForRestartComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERChangedValue(v *TAIListForRestartComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERLegacy(v *TAIListForRestartComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERNewValue(v *TAIListForRestartComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIListForRestartCompleteMethodMarshalAPERPlanned(v *TAIListForRestartComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIListForRestartCompleteMethodUnmarshalAPERLegacy(v *TAIListForRestartComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIListForRestartCompleteMethodUnmarshalAPERWithOptions(v *TAIListForRestartComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIListforMDTCompleteFieldPerPadding(v *TAIListforMDTComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIListforMDTCompleteFieldReceived(v *TAIListforMDTComplete) *bool { return &v.received }
func BridgeTAIListforMDTCompleteFieldReceivedAbsolute(v *TAIListforMDTComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAIListforMDTCompleteFieldReceivedBytes(v *TAIListforMDTComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIListforMDTCompleteFieldReceivedLocation(v *TAIListforMDTComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIListforMDTCompleteFieldReplay(v *TAIListforMDTComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIListforMDTCompleteFieldStream(v *TAIListforMDTComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeTAIListforMDTCompleteFieldWithoutReplay(v *TAIListforMDTComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERBudget(v *TAIListforMDTComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERBudgetValue(v *TAIListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERChanged(v *TAIListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERChangedValue(v *TAIListforMDTComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERLegacy(v *TAIListforMDTComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERNewValue(v *TAIListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIListforMDTCompleteMethodMarshalAPERPlanned(v *TAIListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIListforMDTCompleteMethodUnmarshalAPERLegacy(v *TAIListforMDTComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIListforMDTCompleteMethodUnmarshalAPERWithOptions(v *TAIListforMDTComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIListforQMCCompleteFieldPerPadding(v *TAIListforQMCComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIListforQMCCompleteFieldReceived(v *TAIListforQMCComplete) *bool { return &v.received }
func BridgeTAIListforQMCCompleteFieldReceivedAbsolute(v *TAIListforQMCComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAIListforQMCCompleteFieldReceivedBytes(v *TAIListforQMCComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIListforQMCCompleteFieldReceivedLocation(v *TAIListforQMCComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIListforQMCCompleteFieldReplay(v *TAIListforQMCComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIListforQMCCompleteFieldStream(v *TAIListforQMCComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeTAIListforQMCCompleteFieldWithoutReplay(v *TAIListforQMCComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERBudget(v *TAIListforQMCComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERBudgetValue(v *TAIListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERChanged(v *TAIListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERChangedValue(v *TAIListforQMCComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERLegacy(v *TAIListforQMCComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERNewValue(v *TAIListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIListforQMCCompleteMethodMarshalAPERPlanned(v *TAIListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIListforQMCCompleteMethodUnmarshalAPERLegacy(v *TAIListforQMCComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIListforQMCCompleteMethodUnmarshalAPERWithOptions(v *TAIListforQMCComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAIListforWarningCompleteFieldPerPadding(v *TAIListforWarningComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAIListforWarningCompleteFieldReceived(v *TAIListforWarningComplete) *bool {
	return &v.received
}
func BridgeTAIListforWarningCompleteFieldReceivedAbsolute(v *TAIListforWarningComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAIListforWarningCompleteFieldReceivedBytes(v *TAIListforWarningComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAIListforWarningCompleteFieldReceivedLocation(v *TAIListforWarningComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAIListforWarningCompleteFieldReplay(v *TAIListforWarningComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeTAIListforWarningCompleteFieldStream(v *TAIListforWarningComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeTAIListforWarningCompleteFieldWithoutReplay(v *TAIListforWarningComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERBudget(v *TAIListforWarningComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERBudgetValue(v *TAIListforWarningComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERChanged(v *TAIListforWarningComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERChangedValue(v *TAIListforWarningComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERLegacy(v *TAIListforWarningComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERNewValue(v *TAIListforWarningComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAIListforWarningCompleteMethodMarshalAPERPlanned(v *TAIListforWarningComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAIListforWarningCompleteMethodUnmarshalAPERLegacy(v *TAIListforWarningComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAIListforWarningCompleteMethodUnmarshalAPERWithOptions(v *TAIListforWarningComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAListforMDTCompleteFieldPerPadding(v *TAListforMDTComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAListforMDTCompleteFieldReceived(v *TAListforMDTComplete) *bool { return &v.received }
func BridgeTAListforMDTCompleteFieldReceivedAbsolute(v *TAListforMDTComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAListforMDTCompleteFieldReceivedBytes(v *TAListforMDTComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAListforMDTCompleteFieldReceivedLocation(v *TAListforMDTComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAListforMDTCompleteFieldReplay(v *TAListforMDTComplete) *aper.Snapshot { return &v.replay }
func BridgeTAListforMDTCompleteFieldStream(v *TAListforMDTComplete) *aper.WireSpan { return &v.stream }
func BridgeTAListforMDTCompleteFieldWithoutReplay(v *TAListforMDTComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAListforMDTCompleteMethodMarshalAPERBudget(v *TAListforMDTComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAListforMDTCompleteMethodMarshalAPERBudgetValue(v *TAListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAListforMDTCompleteMethodMarshalAPERChanged(v *TAListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAListforMDTCompleteMethodMarshalAPERChangedValue(v *TAListforMDTComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAListforMDTCompleteMethodMarshalAPERLegacy(v *TAListforMDTComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAListforMDTCompleteMethodMarshalAPERNewValue(v *TAListforMDTComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAListforMDTCompleteMethodMarshalAPERPlanned(v *TAListforMDTComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAListforMDTCompleteMethodUnmarshalAPERLegacy(v *TAListforMDTComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAListforMDTCompleteMethodUnmarshalAPERWithOptions(v *TAListforMDTComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTAListforQMCCompleteFieldPerPadding(v *TAListforQMCComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeTAListforQMCCompleteFieldReceived(v *TAListforQMCComplete) *bool { return &v.received }
func BridgeTAListforQMCCompleteFieldReceivedAbsolute(v *TAListforQMCComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeTAListforQMCCompleteFieldReceivedBytes(v *TAListforQMCComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeTAListforQMCCompleteFieldReceivedLocation(v *TAListforQMCComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeTAListforQMCCompleteFieldReplay(v *TAListforQMCComplete) *aper.Snapshot { return &v.replay }
func BridgeTAListforQMCCompleteFieldStream(v *TAListforQMCComplete) *aper.WireSpan { return &v.stream }
func BridgeTAListforQMCCompleteFieldWithoutReplay(v *TAListforQMCComplete) *bool {
	return &v.withoutReplay
}
func BridgeTAListforQMCCompleteMethodMarshalAPERBudget(v *TAListforQMCComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTAListforQMCCompleteMethodMarshalAPERBudgetValue(v *TAListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTAListforQMCCompleteMethodMarshalAPERChanged(v *TAListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTAListforQMCCompleteMethodMarshalAPERChangedValue(v *TAListforQMCComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTAListforQMCCompleteMethodMarshalAPERLegacy(v *TAListforQMCComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTAListforQMCCompleteMethodMarshalAPERNewValue(v *TAListforQMCComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTAListforQMCCompleteMethodMarshalAPERPlanned(v *TAListforQMCComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTAListforQMCCompleteMethodUnmarshalAPERLegacy(v *TAListforQMCComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTAListforQMCCompleteMethodUnmarshalAPERWithOptions(v *TAListforQMCComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldPerPadding(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldReceived(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *bool {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldReceivedAbsolute(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldReceivedBytes(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldReceivedLocation(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldReplay(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldStream(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionListResAckComplete) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERBudget(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERBudgetValue(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERChanged(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERChangedValue(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionListResAckComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERNewValue(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodMarshalAPERPlanned(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodUnmarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionListResAckCompleteMethodUnmarshalAPERWithOptions(v *UEAssociatedLogicalS1ConnectionListResAckComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldPerPadding(v *UEAssociatedLogicalS1ConnectionListResComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldReceived(v *UEAssociatedLogicalS1ConnectionListResComplete) *bool {
	return &v.received
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldReceivedAbsolute(v *UEAssociatedLogicalS1ConnectionListResComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldReceivedBytes(v *UEAssociatedLogicalS1ConnectionListResComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldReceivedLocation(v *UEAssociatedLogicalS1ConnectionListResComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldReplay(v *UEAssociatedLogicalS1ConnectionListResComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldStream(v *UEAssociatedLogicalS1ConnectionListResComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteFieldWithoutReplay(v *UEAssociatedLogicalS1ConnectionListResComplete) *bool {
	return &v.withoutReplay
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERBudget(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERBudgetValue(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERChanged(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERChangedValue(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionListResComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERNewValue(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodMarshalAPERPlanned(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodUnmarshalAPERLegacy(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEAssociatedLogicalS1ConnectionListResCompleteMethodUnmarshalAPERWithOptions(v *UEAssociatedLogicalS1ConnectionListResComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEHistoryInformationCompleteFieldPerPadding(v *UEHistoryInformationComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeUEHistoryInformationCompleteFieldReceived(v *UEHistoryInformationComplete) *bool {
	return &v.received
}
func BridgeUEHistoryInformationCompleteFieldReceivedAbsolute(v *UEHistoryInformationComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeUEHistoryInformationCompleteFieldReceivedBytes(v *UEHistoryInformationComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEHistoryInformationCompleteFieldReceivedLocation(v *UEHistoryInformationComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEHistoryInformationCompleteFieldReplay(v *UEHistoryInformationComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeUEHistoryInformationCompleteFieldStream(v *UEHistoryInformationComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeUEHistoryInformationCompleteFieldWithoutReplay(v *UEHistoryInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERBudget(v *UEHistoryInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERBudgetValue(v *UEHistoryInformationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERChanged(v *UEHistoryInformationComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERChangedValue(v *UEHistoryInformationComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERLegacy(v *UEHistoryInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERNewValue(v *UEHistoryInformationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEHistoryInformationCompleteMethodMarshalAPERPlanned(v *UEHistoryInformationComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEHistoryInformationCompleteMethodUnmarshalAPERLegacy(v *UEHistoryInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEHistoryInformationCompleteMethodUnmarshalAPERWithOptions(v *UEHistoryInformationComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkNASTransportAPERValueFieldContext(v *UplinkNASTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportAPERValueFieldReceived(v *UplinkNASTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkNASTransportAPERValueFieldReplay(v *UplinkNASTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkNASTransportAPERValueFieldWithoutReplay(v *UplinkNASTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkNASTransportFieldExtCount(v *UplinkNASTransport) *int64   { return &v.extCount }
func BridgeUplinkNASTransportFieldExtData(v *UplinkNASTransport) *[][]byte { return &v.extData }
func BridgeUplinkNASTransportFieldExtOrigin(v *UplinkNASTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUplinkNASTransportFieldExtPresent(v *UplinkNASTransport) *[]bool       { return &v.extPresent }
func BridgeUplinkNASTransportFieldExtWire(v *UplinkNASTransport) *[]aper.WireSpan { return &v.extWire }
func BridgeUplinkNASTransportFieldPerExtPadding(v *UplinkNASTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUplinkNASTransportFieldPerPadding(v *UplinkNASTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkNASTransportFieldProtocolIEsIndef(v *UplinkNASTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeUplinkNASTransportFieldReceived(v *UplinkNASTransport) *bool { return &v.received }
func BridgeUplinkNASTransportFieldReceivedAbsolute(v *UplinkNASTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkNASTransportFieldReceivedBytes(v *UplinkNASTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkNASTransportFieldReceivedLocation(v *UplinkNASTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkNASTransportFieldReplay(v *UplinkNASTransport) *aper.Snapshot { return &v.replay }
func BridgeUplinkNASTransportFieldStream(v *UplinkNASTransport) *aper.WireSpan { return &v.stream }
func BridgeUplinkNASTransportFieldWithoutReplay(v *UplinkNASTransport) *bool   { return &v.withoutReplay }
func BridgeUplinkNASTransportMethodMarshalAPERBudget(v *UplinkNASTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkNASTransportMethodMarshalAPERBudgetValue(v *UplinkNASTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUplinkNASTransportMethodMarshalAPERChanged(v *UplinkNASTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUplinkNASTransportMethodMarshalAPERChangedValue(v *UplinkNASTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUplinkNASTransportMethodMarshalAPERLegacy(v *UplinkNASTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUplinkNASTransportMethodMarshalAPERNewValue(v *UplinkNASTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUplinkNASTransportMethodMarshalAPERPlanned(v *UplinkNASTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUplinkNASTransportMethodMarshalAPERTo(v *UplinkNASTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkNASTransportMethodUnmarshalAPERFrom(v *UplinkNASTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkNASTransportMethodUnmarshalAPERLegacy(v *UplinkNASTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUplinkNASTransportMethodUnmarshalAPERWithOptions(v *UplinkNASTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkNASTransportValueCodecFieldCapture(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, aper.DecodeState) (UplinkNASTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNASTransportValueCodecFieldCompare(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNASTransportValueCodecFieldContext(v *UplinkNASTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNASTransportValueCodecFieldDecode(v *UplinkNASTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkNASTransport, error) {
	return &v.decode
}
func BridgeUplinkNASTransportValueCodecFieldEncode(v *UplinkNASTransportValueCodec) *func(UplinkNASTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNASTransportValueCodecFieldPath(v *UplinkNASTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNASTransportValueCodecMethodEncodeBudgetValue(v UplinkNASTransportValueCodec, a0 UplinkNASTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkNASTransportValueCodecMethodEncodeChanged(v UplinkNASTransportValueCodec, a0 UplinkNASTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkNonUEAssociatedLPPaTransportAPERValueFieldContext(v *UplinkNonUEAssociatedLPPaTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNonUEAssociatedLPPaTransportAPERValueFieldReceived(v *UplinkNonUEAssociatedLPPaTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkNonUEAssociatedLPPaTransportAPERValueFieldReplay(v *UplinkNonUEAssociatedLPPaTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkNonUEAssociatedLPPaTransportAPERValueFieldWithoutReplay(v *UplinkNonUEAssociatedLPPaTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldExtCount(v *UplinkNonUEAssociatedLPPaTransport) *int64 {
	return &v.extCount
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldExtData(v *UplinkNonUEAssociatedLPPaTransport) *[][]byte {
	return &v.extData
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldExtOrigin(v *UplinkNonUEAssociatedLPPaTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldExtPresent(v *UplinkNonUEAssociatedLPPaTransport) *[]bool {
	return &v.extPresent
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldExtWire(v *UplinkNonUEAssociatedLPPaTransport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldPerExtPadding(v *UplinkNonUEAssociatedLPPaTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldPerPadding(v *UplinkNonUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldProtocolIEsIndef(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceived(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedAbsolute(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedBytes(v *UplinkNonUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReceivedLocation(v *UplinkNonUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldReplay(v *UplinkNonUEAssociatedLPPaTransport) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldStream(v *UplinkNonUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.stream
}
func BridgeUplinkNonUEAssociatedLPPaTransportFieldWithoutReplay(v *UplinkNonUEAssociatedLPPaTransport) *bool {
	return &v.withoutReplay
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudgetValue(v *UplinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERChanged(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERChangedValue(v *UplinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERLegacy(v *UplinkNonUEAssociatedLPPaTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERNewValue(v *UplinkNonUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERPlanned(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERTo(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *UplinkNonUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERLegacy(v *UplinkNonUEAssociatedLPPaTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUplinkNonUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *UplinkNonUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCapture(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldCompare(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldContext(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldDecode(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkNonUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldEncode(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *func(UplinkNonUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecFieldPath(v *UplinkNonUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecMethodEncodeBudgetValue(v UplinkNonUEAssociatedLPPaTransportValueCodec, a0 UplinkNonUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkNonUEAssociatedLPPaTransportValueCodecMethodEncodeChanged(v UplinkNonUEAssociatedLPPaTransportValueCodec, a0 UplinkNonUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkS1cdma2000tunnellingAPERValueFieldContext(v *UplinkS1cdma2000tunnellingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingAPERValueFieldReceived(v *UplinkS1cdma2000tunnellingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingAPERValueFieldReplay(v *UplinkS1cdma2000tunnellingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingAPERValueFieldWithoutReplay(v *UplinkS1cdma2000tunnellingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingFieldExtCount(v *UplinkS1cdma2000tunnelling) *int64 {
	return &v.extCount
}
func BridgeUplinkS1cdma2000tunnellingFieldExtData(v *UplinkS1cdma2000tunnelling) *[][]byte {
	return &v.extData
}
func BridgeUplinkS1cdma2000tunnellingFieldExtOrigin(v *UplinkS1cdma2000tunnelling) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUplinkS1cdma2000tunnellingFieldExtPresent(v *UplinkS1cdma2000tunnelling) *[]bool {
	return &v.extPresent
}
func BridgeUplinkS1cdma2000tunnellingFieldExtWire(v *UplinkS1cdma2000tunnelling) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUplinkS1cdma2000tunnellingFieldPerExtPadding(v *UplinkS1cdma2000tunnelling) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUplinkS1cdma2000tunnellingFieldPerPadding(v *UplinkS1cdma2000tunnelling) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkS1cdma2000tunnellingFieldProtocolIEsIndef(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.protocolIEsIndef
}
func BridgeUplinkS1cdma2000tunnellingFieldReceived(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.received
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedAbsolute(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedBytes(v *UplinkS1cdma2000tunnelling) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkS1cdma2000tunnellingFieldReceivedLocation(v *UplinkS1cdma2000tunnelling) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkS1cdma2000tunnellingFieldReplay(v *UplinkS1cdma2000tunnelling) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkS1cdma2000tunnellingFieldStream(v *UplinkS1cdma2000tunnelling) *aper.WireSpan {
	return &v.stream
}
func BridgeUplinkS1cdma2000tunnellingFieldWithoutReplay(v *UplinkS1cdma2000tunnelling) *bool {
	return &v.withoutReplay
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v *UplinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudgetValue(v *UplinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERChanged(v *UplinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERChangedValue(v *UplinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERLegacy(v *UplinkS1cdma2000tunnelling) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERNewValue(v *UplinkS1cdma2000tunnelling, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERPlanned(v *UplinkS1cdma2000tunnelling, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERTo(v *UplinkS1cdma2000tunnelling, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERFrom(v *UplinkS1cdma2000tunnelling, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERLegacy(v *UplinkS1cdma2000tunnelling, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUplinkS1cdma2000tunnellingMethodUnmarshalAPERWithOptions(v *UplinkS1cdma2000tunnelling, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldCapture(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, aper.DecodeState) (UplinkS1cdma2000tunnelling, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldCompare(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldContext(v *UplinkS1cdma2000tunnellingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldDecode(v *UplinkS1cdma2000tunnellingValueCodec) *func([]byte, aper.DecodeState) (UplinkS1cdma2000tunnelling, error) {
	return &v.decode
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldEncode(v *UplinkS1cdma2000tunnellingValueCodec) *func(UplinkS1cdma2000tunnelling, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkS1cdma2000tunnellingValueCodecFieldPath(v *UplinkS1cdma2000tunnellingValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkS1cdma2000tunnellingValueCodecMethodEncodeBudgetValue(v UplinkS1cdma2000tunnellingValueCodec, a0 UplinkS1cdma2000tunnelling, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkS1cdma2000tunnellingValueCodecMethodEncodeChanged(v UplinkS1cdma2000tunnellingValueCodec, a0 UplinkS1cdma2000tunnelling, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUplinkUEAssociatedLPPaTransportAPERValueFieldContext(v *UplinkUEAssociatedLPPaTransportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkUEAssociatedLPPaTransportAPERValueFieldReceived(v *UplinkUEAssociatedLPPaTransportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUplinkUEAssociatedLPPaTransportAPERValueFieldReplay(v *UplinkUEAssociatedLPPaTransportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkUEAssociatedLPPaTransportAPERValueFieldWithoutReplay(v *UplinkUEAssociatedLPPaTransportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUplinkUEAssociatedLPPaTransportFieldExtCount(v *UplinkUEAssociatedLPPaTransport) *int64 {
	return &v.extCount
}
func BridgeUplinkUEAssociatedLPPaTransportFieldExtData(v *UplinkUEAssociatedLPPaTransport) *[][]byte {
	return &v.extData
}
func BridgeUplinkUEAssociatedLPPaTransportFieldExtOrigin(v *UplinkUEAssociatedLPPaTransport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUplinkUEAssociatedLPPaTransportFieldExtPresent(v *UplinkUEAssociatedLPPaTransport) *[]bool {
	return &v.extPresent
}
func BridgeUplinkUEAssociatedLPPaTransportFieldExtWire(v *UplinkUEAssociatedLPPaTransport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUplinkUEAssociatedLPPaTransportFieldPerExtPadding(v *UplinkUEAssociatedLPPaTransport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUplinkUEAssociatedLPPaTransportFieldPerPadding(v *UplinkUEAssociatedLPPaTransport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUplinkUEAssociatedLPPaTransportFieldProtocolIEsIndef(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.protocolIEsIndef
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceived(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.received
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedAbsolute(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.receivedAbsolute
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedBytes(v *UplinkUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReceivedLocation(v *UplinkUEAssociatedLPPaTransport) *aper.Location {
	return &v.receivedLocation
}
func BridgeUplinkUEAssociatedLPPaTransportFieldReplay(v *UplinkUEAssociatedLPPaTransport) *aper.Snapshot {
	return &v.replay
}
func BridgeUplinkUEAssociatedLPPaTransportFieldStream(v *UplinkUEAssociatedLPPaTransport) *aper.WireSpan {
	return &v.stream
}
func BridgeUplinkUEAssociatedLPPaTransportFieldWithoutReplay(v *UplinkUEAssociatedLPPaTransport) *bool {
	return &v.withoutReplay
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v *UplinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudgetValue(v *UplinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERChanged(v *UplinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERChangedValue(v *UplinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERLegacy(v *UplinkUEAssociatedLPPaTransport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERNewValue(v *UplinkUEAssociatedLPPaTransport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERPlanned(v *UplinkUEAssociatedLPPaTransport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERTo(v *UplinkUEAssociatedLPPaTransport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERFrom(v *UplinkUEAssociatedLPPaTransport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERLegacy(v *UplinkUEAssociatedLPPaTransport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUplinkUEAssociatedLPPaTransportMethodUnmarshalAPERWithOptions(v *UplinkUEAssociatedLPPaTransport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCapture(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, aper.DecodeState) (UplinkUEAssociatedLPPaTransport, aper.Snapshot) {
	return &v.capture
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldCompare(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldContext(v *UplinkUEAssociatedLPPaTransportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldDecode(v *UplinkUEAssociatedLPPaTransportValueCodec) *func([]byte, aper.DecodeState) (UplinkUEAssociatedLPPaTransport, error) {
	return &v.decode
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldEncode(v *UplinkUEAssociatedLPPaTransportValueCodec) *func(UplinkUEAssociatedLPPaTransport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecFieldPath(v *UplinkUEAssociatedLPPaTransportValueCodec) *aper.Path {
	return &v.path
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecMethodEncodeBudgetValue(v UplinkUEAssociatedLPPaTransportValueCodec, a0 UplinkUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUplinkUEAssociatedLPPaTransportValueCodecMethodEncodeChanged(v UplinkUEAssociatedLPPaTransportValueCodec, a0 UplinkUEAssociatedLPPaTransport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUserLocationInformationFieldExtCount(v *UserLocationInformation) *int64 {
	return &v.extCount
}
func BridgeUserLocationInformationFieldExtData(v *UserLocationInformation) *[][]byte {
	return &v.extData
}
func BridgeUserLocationInformationFieldExtOrigin(v *UserLocationInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUserLocationInformationFieldExtPresent(v *UserLocationInformation) *[]bool {
	return &v.extPresent
}
func BridgeUserLocationInformationFieldExtWire(v *UserLocationInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUserLocationInformationFieldIEExtensionsIndef(v *UserLocationInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUserLocationInformationFieldPerExtPadding(v *UserLocationInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUserLocationInformationFieldPerPadding(v *UserLocationInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUserLocationInformationFieldReceived(v *UserLocationInformation) *bool { return &v.received }
func BridgeUserLocationInformationFieldReceivedAbsolute(v *UserLocationInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeUserLocationInformationFieldReceivedBytes(v *UserLocationInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUserLocationInformationFieldReceivedLocation(v *UserLocationInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeUserLocationInformationFieldReplay(v *UserLocationInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeUserLocationInformationFieldStream(v *UserLocationInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeUserLocationInformationFieldWithoutReplay(v *UserLocationInformation) *bool {
	return &v.withoutReplay
}
func BridgeUserLocationInformationMethodMarshalAPERBudget(v *UserLocationInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUserLocationInformationMethodMarshalAPERBudgetValue(v *UserLocationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUserLocationInformationMethodMarshalAPERChanged(v *UserLocationInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUserLocationInformationMethodMarshalAPERChangedValue(v *UserLocationInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUserLocationInformationMethodMarshalAPERLegacy(v *UserLocationInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUserLocationInformationMethodMarshalAPERNewValue(v *UserLocationInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUserLocationInformationMethodMarshalAPERPlanned(v *UserLocationInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUserLocationInformationMethodMarshalAPERTo(v *UserLocationInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUserLocationInformationMethodUnmarshalAPERFrom(v *UserLocationInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUserLocationInformationMethodUnmarshalAPERLegacy(v *UserLocationInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUserLocationInformationMethodUnmarshalAPERWithOptions(v *UserLocationInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasConfigNameListCompleteFieldPerPadding(v *WLANMeasConfigNameListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWLANMeasConfigNameListCompleteFieldReceived(v *WLANMeasConfigNameListComplete) *bool {
	return &v.received
}
func BridgeWLANMeasConfigNameListCompleteFieldReceivedAbsolute(v *WLANMeasConfigNameListComplete) *bool {
	return &v.receivedAbsolute
}
func BridgeWLANMeasConfigNameListCompleteFieldReceivedBytes(v *WLANMeasConfigNameListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasConfigNameListCompleteFieldReceivedLocation(v *WLANMeasConfigNameListComplete) *aper.Location {
	return &v.receivedLocation
}
func BridgeWLANMeasConfigNameListCompleteFieldReplay(v *WLANMeasConfigNameListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasConfigNameListCompleteFieldStream(v *WLANMeasConfigNameListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasConfigNameListCompleteFieldWithoutReplay(v *WLANMeasConfigNameListComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERBudget(v *WLANMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERBudgetValue(v *WLANMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERChanged(v *WLANMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERChangedValue(v *WLANMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERLegacy(v *WLANMeasConfigNameListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERNewValue(v *WLANMeasConfigNameListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWLANMeasConfigNameListCompleteMethodMarshalAPERPlanned(v *WLANMeasConfigNameListComplete, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWLANMeasConfigNameListCompleteMethodUnmarshalAPERLegacy(v *WLANMeasConfigNameListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasConfigNameListCompleteMethodUnmarshalAPERWithOptions(v *WLANMeasConfigNameListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *ERABModificationIndicationIEValue) Selected() (any, bool) {
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
	case 199:
		if value, ok := v.AsERABToBeModifiedListBearerModInd(); ok {
			return value, true
		}
	case 201:
		if value, ok := v.AsERABNotToBeModifiedListBearerModInd(); ok {
			return value, true
		}
	case 226:
		if value, ok := v.AsCSGMembershipInfo(); ok {
			return value, true
		}
	case 176:
		if value, ok := v.AsTunnelInformationForBBF(); ok {
			return value, true
		}
	case 264:
		if value, ok := v.AsSecondaryRATDataUsageReportList(); ok {
			return value, true
		}
	case 189:
		if value, ok := v.AsUserLocationInformation(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *PWSRestartIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 182:
		if value, ok := v.AsECGIListForRestart(); ok {
			return value, true
		}
	case 59:
		if value, ok := v.AsGlobalENBID(); ok {
			return value, true
		}
	case 188:
		if value, ok := v.AsTAIListForRestart(); ok {
			return value, true
		}
	case 190:
		if value, ok := v.AsEmergencyAreaIDListForRestart(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResetAcknowledgeIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 93:
		if value, ok := v.AsUEAssociatedLogicalS1ConnectionListResAck(); ok {
			return value, true
		}
	case 58:
		if value, ok := v.AsCriticalityDiagnostics(); ok {
			return value, true
		}
	}
	return nil, false
}
