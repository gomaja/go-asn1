// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s33 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s33

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
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// WriteReplaceWarningRequestIEContainer is the concrete ProtocolIEContainer[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEContainer []WriteReplaceWarningRequestIEField

// WriteReplaceWarningRequestIEField is the concrete ProtocolIEField[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         WriteReplaceWarningRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEField) WithoutReplay() WriteReplaceWarningRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *WriteReplaceWarningRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *WriteReplaceWarningRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *WriteReplaceWarningRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningRequestIEField{}
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
	var zero WriteReplaceWarningRequestIEValue

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

// ENBDirectInformationTransferIEContainer is the concrete ProtocolIEContainer[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEContainer []ENBDirectInformationTransferIEField

// ENBDirectInformationTransferIEField is the concrete ProtocolIEField[ENBDirectInformationTransferIEValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MMEDirectInformationTransferIEContainer is the concrete ProtocolIEContainer[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEContainer []MMEDirectInformationTransferIEField

// MMEDirectInformationTransferIEField is the concrete ProtocolIEField[MMEDirectInformationTransferIEValue].
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}
func BridgeKillRequestIEValueCaptureS1APProtocolIEContainer(v *s32.KillRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APProtocolIEContainer(v *s32.KillRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeKillResponseIEValueCaptureS1APProtocolIEContainer(v *s32.KillResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APProtocolIEContainer(v *s32.KillResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APProtocolIEContainer(v *s31.LocationReportIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APProtocolIEContainer(v *s31.LocationReportIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeRecommendedENBItemIEValueCaptureS1APProtocolIESingleContainer(v *s32.RecommendedENBItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(v *s32.RecommendedENBItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeRecommendedENBItemIEValueCompareS1APProtocolIEField(v, s)
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

// TAIItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[TAIItemIEValue].
type TAIItemIEValueProtocolIESingleContainer = TAIItemIEField

// ENBDirectInformationTransferInterSystemInformationTransferTypeIEBinding is the concrete IEBinding[InterSystemInformationTransferType, ENBDirectInformationTransferIEValue].
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

// MMEDirectInformationTransferInterSystemInformationTransferTypeIEBinding is the concrete IEBinding[InterSystemInformationTransferType, MMEDirectInformationTransferIEValue].
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

// TAIItemTAIItemIEBinding is the concrete IEBinding[TAIItem, TAIItemIEValue].
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

// TAIItemIEField is the concrete ProtocolIEField[TAIItemIEValue].
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
	value, err := zero.decode(v.Id, raw)
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

// WriteReplaceWarningRequestMessageIdentifierIEBinding is the concrete IEBinding[MessageIdentifier, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestMessageIdentifierIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MessageIdentifierValueCodec
	inject func(s00.MessageIdentifier,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.MessageIdentifier,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestMessageIdentifierIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestMessageIdentifierIEBinding) Codec() s01.MessageIdentifierValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestMessageIdentifierIEBinding) New(value s00.MessageIdentifier,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMessageIdentifierValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestMessageIdentifierIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.MessageIdentifier,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestSerialNumberIEBinding is the concrete IEBinding[SerialNumber, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestSerialNumberIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SerialNumberValueCodec
	inject func(s00.SerialNumber,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.SerialNumber,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestSerialNumberIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestSerialNumberIEBinding) Codec() s01.SerialNumberValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestSerialNumberIEBinding) New(value s00.SerialNumber,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSerialNumberValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestSerialNumberIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.SerialNumber,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestWarningAreaListIEBinding is the concrete IEBinding[WarningAreaList, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestWarningAreaListIEBinding struct {
	info   s00.FieldInfo
	codec  s32.WarningAreaListValueCodec
	inject func(s32.WarningAreaList,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s32.WarningAreaList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Codec() s32.WarningAreaListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) New(value s32.WarningAreaList,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s32.BridgeWarningAreaListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningAreaListIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s32.WarningAreaList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestRepetitionPeriodIEBinding is the concrete IEBinding[RepetitionPeriod, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestRepetitionPeriodIEBinding struct {
	info   s00.FieldInfo
	codec  s01.RepetitionPeriodValueCodec
	inject func(s00.RepetitionPeriod,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.RepetitionPeriod,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestRepetitionPeriodIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestRepetitionPeriodIEBinding) Codec() s01.RepetitionPeriodValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestRepetitionPeriodIEBinding) New(value s00.RepetitionPeriod,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeRepetitionPeriodValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestRepetitionPeriodIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.RepetitionPeriod,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding is the concrete IEBinding[ExtendedRepetitionPeriod, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ExtendedRepetitionPeriodValueCodec
	inject func(s00.ExtendedRepetitionPeriod,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.ExtendedRepetitionPeriod,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) Codec() s00.ExtendedRepetitionPeriodValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) New(value s00.ExtendedRepetitionPeriod,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeExtendedRepetitionPeriodValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.ExtendedRepetitionPeriod,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding is the concrete IEBinding[NumberofBroadcastRequest, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NumberofBroadcastRequestValueCodec
	inject func(s00.NumberofBroadcastRequest,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.NumberofBroadcastRequest,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) Codec() s01.NumberofBroadcastRequestValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) New(value s00.NumberofBroadcastRequest,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNumberofBroadcastRequestValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.NumberofBroadcastRequest,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestWarningTypeIEBinding is the concrete IEBinding[WarningType, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestWarningTypeIEBinding struct {
	info   s00.FieldInfo
	codec  s02.WarningTypeValueCodec
	inject func(s00.WarningType,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.WarningType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningTypeIEBinding) Codec() s02.WarningTypeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningTypeIEBinding) New(value s00.WarningType,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeWarningTypeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningTypeIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.WarningType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestWarningSecurityInfoIEBinding is the concrete IEBinding[WarningSecurityInfo, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestWarningSecurityInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s02.WarningSecurityInfoValueCodec
	inject func(s00.WarningSecurityInfo,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.WarningSecurityInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningSecurityInfoIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningSecurityInfoIEBinding) Codec() s02.WarningSecurityInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningSecurityInfoIEBinding) New(value s00.WarningSecurityInfo,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeWarningSecurityInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningSecurityInfoIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.WarningSecurityInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestDataCodingSchemeIEBinding is the concrete IEBinding[DataCodingScheme, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestDataCodingSchemeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DataCodingSchemeValueCodec
	inject func(s00.DataCodingScheme,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.DataCodingScheme,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestDataCodingSchemeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestDataCodingSchemeIEBinding) Codec() s00.DataCodingSchemeValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestDataCodingSchemeIEBinding) New(value s00.DataCodingScheme,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDataCodingSchemeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestDataCodingSchemeIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.DataCodingScheme,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestWarningMessageContentsIEBinding is the concrete IEBinding[WarningMessageContents, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestWarningMessageContentsIEBinding struct {
	info   s00.FieldInfo
	codec  s02.WarningMessageContentsValueCodec
	inject func(s00.WarningMessageContents,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.WarningMessageContents,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningMessageContentsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningMessageContentsIEBinding) Codec() s02.WarningMessageContentsValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningMessageContentsIEBinding) New(value s00.WarningMessageContents,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeWarningMessageContentsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningMessageContentsIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.WarningMessageContents,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding is the concrete IEBinding[ConcurrentWarningMessageIndicator, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ConcurrentWarningMessageIndicatorValueCodec
	inject func(s00.ConcurrentWarningMessageIndicator,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.ConcurrentWarningMessageIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) Codec() s00.ConcurrentWarningMessageIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) New(value s00.ConcurrentWarningMessageIndicator,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.ConcurrentWarningMessageIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding is the concrete IEBinding[WarningAreaCoordinates, WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding struct {
	info   s00.FieldInfo
	codec  s02.WarningAreaCoordinatesValueCodec
	inject func(s00.WarningAreaCoordinates,

	) WriteReplaceWarningRequestIEValue

	get func(*WriteReplaceWarningRequestIEValue,

	) (*s00.WarningAreaCoordinates,

		bool)
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) Codec() s02.WarningAreaCoordinatesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) New(value s00.WarningAreaCoordinates,

) (WriteReplaceWarningRequestIEField, error) {
	if b.inject == nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeWarningAreaCoordinatesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return WriteReplaceWarningRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) Get(field *WriteReplaceWarningRequestIEField) (*s00.WarningAreaCoordinates,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// KillRequestValueCodec is the concrete ValueCodec[KillRequest].
type KillRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillRequest,

		error)
	encode func(KillRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillRequest, aper.DecodeState,

	) (KillRequest, aper.Snapshot,

	)
	compare func(KillRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillRequestValueCodec) New(value KillRequest,

) (KillRequestAPERValue, error) {
	if c.encode == nil {
		return KillRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillRequestValueCodec) EncodeAPER(value KillRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c KillRequestValueCodec) encodeBudgetValue(value KillRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillRequestValueCodec) encodeChanged(value KillRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillResponseValueCodec is the concrete ValueCodec[KillResponse].
type KillResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (KillResponse,

		error)
	encode func(KillResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(KillResponse, aper.DecodeState,

	) (KillResponse, aper.Snapshot,

	)
	compare func(KillResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillResponseValueCodec) New(value KillResponse,

) (KillResponseAPERValue, error) {
	if c.encode == nil {
		return KillResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillResponseValueCodec) EncodeAPER(value KillResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c KillResponseValueCodec) encodeBudgetValue(value KillResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillResponseValueCodec) encodeChanged(value KillResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LocationReportValueCodec is the concrete ValueCodec[LocationReport].
type LocationReportValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (LocationReport,

		error)
	encode func(LocationReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(LocationReport, aper.DecodeState,

	) (LocationReport, aper.Snapshot,

	)
	compare func(LocationReport, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LocationReportValueCodec) New(value LocationReport,

) (LocationReportAPERValue, error) {
	if c.encode == nil {
		return LocationReportAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LocationReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LocationReportAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LocationReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LocationReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LocationReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LocationReportAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LocationReportAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LocationReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LocationReportAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LocationReportValueCodec) EncodeAPER(value LocationReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LocationReportValueCodec) encodeBudgetValue(value LocationReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LocationReportValueCodec) encodeChanged(value LocationReport,

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

// RecommendedENBsForPagingValueCodec is the concrete ValueCodec[RecommendedENBsForPaging].
type RecommendedENBsForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (RecommendedENBsForPaging,

		error)
	encode func(RecommendedENBsForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(RecommendedENBsForPaging, aper.DecodeState,

	) (RecommendedENBsForPaging, aper.Snapshot,

	)
	compare func(RecommendedENBsForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RecommendedENBsForPagingValueCodec) New(value RecommendedENBsForPaging,

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
func (c RecommendedENBsForPagingValueCodec) encodeBudgetValue(value RecommendedENBsForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RecommendedENBsForPagingValueCodec) encodeChanged(value RecommendedENBsForPaging,

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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeLocationReportIEValueValidateS1APIEContainer(fields s31.LocationReportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s31.BridgeLocationReportIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s31.BridgeLocationReportIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s31.BridgeLocationReportIEValueMethodRule(field.Value).Assignment
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
func BridgeKillRequestIEValueValidateS1APIEContainer(fields s32.KillRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s32.BridgeKillRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeKillRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeKillRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeKillResponseIEValueValidateS1APIEContainer(fields s32.KillResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s32.BridgeKillResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeKillResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeKillResponseIEValueMethodRule(field.Value).Assignment
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// TAIItemIEContainer is the concrete ProtocolIEContainer[TAIItemIEValue].
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
func KillRequestIEValueERABIEContainerListCodec(table s00.KillRequestIEValueIETable) s32.KillRequestIEValueERABIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s32.KillRequestIEValueERABIEContainerListValueCodec {
		sealed := s32.KillRequestIEValueERABIEContainerListValueCodec{}
		*s32.BridgeKillRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillRequestIEValueERABIEContainerList, error) {
			value, err := (*s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillRequestIEValueERABIEContainerList(value), err
		}
		*s32.BridgeKillRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillRequestIEContainerValueCodecFieldEncode(&codec))(s32.KillRequestIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillRequestIEValueERABIEContainerList, options aper.DecodeState) (s32.KillRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func KillResponseIEValueERABIEContainerListCodec(table s00.KillResponseIEValueIETable) s32.KillResponseIEValueERABIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s32.KillResponseIEValueERABIEContainerListValueCodec {
		sealed := s32.KillResponseIEValueERABIEContainerListValueCodec{}
		*s32.BridgeKillResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillResponseIEValueERABIEContainerList, error) {
			value, err := (*s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillResponseIEValueERABIEContainerList(value), err
		}
		*s32.BridgeKillResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillResponseIEContainerValueCodecFieldEncode(&codec))(s32.KillResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillResponseIEValueERABIEContainerList, options aper.DecodeState) (s32.KillResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LocationReportIEValueERABIEContainerListCodec(table s00.LocationReportIEValueIETable) s31.LocationReportIEValueERABIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.LocationReportIEValueERABIEContainerListValueCodec{}
	}
	return func() s31.LocationReportIEValueERABIEContainerListValueCodec {
		sealed := s31.LocationReportIEValueERABIEContainerListValueCodec{}
		*s31.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.LocationReportIEValueERABIEContainerList, error) {
			value, err := (*s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.LocationReportIEValueERABIEContainerList(value), err
		}
		*s31.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.LocationReportIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s31.LocationReportIEContainer(value), fresh, budget)
		}
		*s31.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.LocationReportIEValueERABIEContainerList, options aper.DecodeState) (s31.LocationReportIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.LocationReportIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeLocationReportIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func RecommendedENBItemIEValueERABIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable) s32.RecommendedENBItemIEValueERABIEContainerListValueCodec {
	codec := RecommendedENBItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueERABIEContainerListValueCodec{}
	}
	return func() s32.RecommendedENBItemIEValueERABIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueERABIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueERABIEContainerList, error) {
			value, err := (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.RecommendedENBItemIEValueERABIEContainerList(value), err
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueERABIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
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
func TAIItemIEValueERABIEContainerListCodec(table s00.TAIItemIEValueIETable) TAIItemIEValueERABIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TAIItemIEValueERABIEContainerListValueCodec{}
	}
	return TAIItemIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return TAIItemIEValueERABIEContainerList(value), err
	}, encode: func(value TAIItemIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TAIItemIEContainer(value), fresh, budget)
	}, capture: func(v TAIItemIEValueERABIEContainerList, options aper.DecodeState) (TAIItemIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TAIItemIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTAIItemIEValueCompareS1APERABIEContainerList(&v, &s)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTAIItemExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TAIItemExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIItemExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTargetNgRanNodeIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargetNgRanNodeIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargetNgRanNodeIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
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
			s.End(f, &root,
				false)
			return v, root
		}
		*s11.BridgeTargetRNCIDExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s11.TargetRNCIDExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTargetRNCIDExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
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
					if err := s11.BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
					if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			f := s.
				Begin()
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
func KillRequestIEValueIEFieldTableCodec(table s00.KillRequestIEValueIETable) s32.KillRequestIEFieldValueCodec {
	if !*s00.BridgeKillRequestIEValueIETableFieldBound(&table) {
		return s32.KillRequestIEFieldValueCodec{}
	}
	return func() s32.KillRequestIEFieldValueCodec {
		sealed := s32.KillRequestIEFieldValueCodec{}
		*s32.BridgeKillRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillRequestIEField, error) {
			var field s32.KillRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeKillRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s32.BridgeKillRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s32.KillRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeKillRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeKillRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s32.KillRequestIEField, options aper.DecodeState) (s32.KillRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s32.BridgeKillRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s32.KillRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func KillResponseIEValueIEFieldTableCodec(table s00.KillResponseIEValueIETable) s32.KillResponseIEFieldValueCodec {
	if !*s00.BridgeKillResponseIEValueIETableFieldBound(&table) {
		return s32.KillResponseIEFieldValueCodec{}
	}
	return func() s32.KillResponseIEFieldValueCodec {
		sealed := s32.KillResponseIEFieldValueCodec{}
		*s32.BridgeKillResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillResponseIEField, error) {
			var field s32.KillResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeKillResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s32.BridgeKillResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s32.KillResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeKillResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeKillResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s32.KillResponseIEField, options aper.DecodeState) (s32.KillResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s32.BridgeKillResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s32.KillResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LocationReportIEValueIEFieldTableCodec(table s00.LocationReportIEValueIETable) s31.LocationReportIEFieldValueCodec {
	if !*s00.BridgeLocationReportIEValueIETableFieldBound(&table) {
		return s31.LocationReportIEFieldValueCodec{}
	}
	return func() s31.LocationReportIEFieldValueCodec {
		sealed := s31.LocationReportIEFieldValueCodec{}
		*s31.BridgeLocationReportIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.LocationReportIEField, error) {
			var field s31.LocationReportIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s31.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s31.BridgeLocationReportIEFieldValueCodecFieldEncode(&sealed) = func(field s31.LocationReportIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s31.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s31.BridgeLocationReportIEFieldValueCodecFieldCapture(&sealed) = func(v s31.LocationReportIEField, options aper.DecodeState) (s31.LocationReportIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s31.BridgeLocationReportIEFieldValueCodecFieldCompare(&sealed) = func(v s31.LocationReportIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeLocationReportIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func RecommendedENBItemIEValueIEFieldTableCodec(table s00.RecommendedENBItemIEValueIETable) s32.RecommendedENBItemIEFieldValueCodec {
	if !*s00.BridgeRecommendedENBItemIEValueIETableFieldBound(&table) {
		return s32.RecommendedENBItemIEFieldValueCodec{}
	}
	return func() s32.RecommendedENBItemIEFieldValueCodec {
		sealed := s32.RecommendedENBItemIEFieldValueCodec{}
		*s32.BridgeRecommendedENBItemIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEField, error) {
			var field s32.RecommendedENBItemIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s32.BridgeRecommendedENBItemIEFieldValueCodecFieldEncode(&sealed) = func(field s32.RecommendedENBItemIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeRecommendedENBItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeRecommendedENBItemIEFieldValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEField, options aper.DecodeState) (s32.RecommendedENBItemIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s32.BridgeRecommendedENBItemIEFieldValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBItemIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
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
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
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
		BridgeTAIItemIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
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
func KillRequestIEValueIETableCodec(table s00.KillRequestIEValueIETable, bounds aper.ListBounds) s32.KillRequestIEContainerValueCodec {
	if !*s00.BridgeKillRequestIEValueIETableFieldBound(&table) {
		return s32.KillRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.KillRequestIEContainerValueCodec {
		sealed := s32.KillRequestIEContainerValueCodec{}
		*s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.KillRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.KillRequestIEField
					if err := s32.BridgeKillRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s32.BridgeKillRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.KillRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeKillRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s32.BridgeKillRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s32.KillRequestIEContainer, options aper.DecodeState) (s32.KillRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s32.KillRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func KillResponseIEValueIETableCodec(table s00.KillResponseIEValueIETable, bounds aper.ListBounds) s32.KillResponseIEContainerValueCodec {
	if !*s00.BridgeKillResponseIEValueIETableFieldBound(&table) {
		return s32.KillResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.KillResponseIEContainerValueCodec {
		sealed := s32.KillResponseIEContainerValueCodec{}
		*s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.KillResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.KillResponseIEField
					if err := s32.BridgeKillResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s32.BridgeKillResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.KillResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeKillResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s32.BridgeKillResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s32.KillResponseIEContainer, options aper.DecodeState) (s32.KillResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s32.KillResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LocationReportIEValueIETableCodec(table s00.LocationReportIEValueIETable, bounds aper.ListBounds) s31.LocationReportIEContainerValueCodec {
	if !*s00.BridgeLocationReportIEValueIETableFieldBound(&table) {
		return s31.LocationReportIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s31.LocationReportIEContainerValueCodec {
		sealed := s31.LocationReportIEContainerValueCodec{}
		*s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.LocationReportIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s31.LocationReportIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s31.LocationReportIEField
					if err := s31.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s31.BridgeLocationReportIEContainerValueCodecFieldEncode(&sealed) = func(fields s31.LocationReportIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s31.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s31.BridgeLocationReportIEContainerValueCodecFieldCapture(&sealed) = func(v s31.LocationReportIEContainer, options aper.DecodeState) (s31.LocationReportIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeLocationReportIEContainerValueCodecFieldCompare(&sealed) = func(v s31.LocationReportIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeLocationReportIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func RecommendedENBItemIEValueIETableCodec(table s00.RecommendedENBItemIEValueIETable, bounds aper.ListBounds) s32.RecommendedENBItemIEContainerValueCodec {
	if !*s00.BridgeRecommendedENBItemIEValueIETableFieldBound(&table) {
		return s32.RecommendedENBItemIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.RecommendedENBItemIEContainerValueCodec {
		sealed := s32.RecommendedENBItemIEContainerValueCodec{}
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.RecommendedENBItemIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.RecommendedENBItemIEField
					if err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.RecommendedENBItemIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeRecommendedENBItemIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEContainer, options aper.DecodeState) (s32.RecommendedENBItemIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
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
			s.End(f, &root, false)
			return v, root
		}, compare: func(v TAIItemIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTAIItemIEValueCompareS1APProtocolIEContainer(&v, &s)
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
func KillRequestIEValueProtocolErrorIEContainerListCodec(table s00.KillRequestIEValueIETable) s32.KillRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s32.KillRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.KillRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s32.BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillRequestIEContainerValueCodecFieldEncode(&codec))(s32.KillRequestIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.KillRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeKillRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func KillResponseIEValueProtocolErrorIEContainerListCodec(table s00.KillResponseIEValueIETable) s32.KillResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s32.KillResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.KillResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s32.BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillResponseIEContainerValueCodecFieldEncode(&codec))(s32.KillResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.KillResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeKillResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func LocationReportIEValueProtocolErrorIEContainerListCodec(table s00.LocationReportIEValueIETable) s31.LocationReportIEValueProtocolErrorIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.LocationReportIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s31.LocationReportIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s31.LocationReportIEValueProtocolErrorIEContainerListValueCodec{}
		*s31.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.LocationReportIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.LocationReportIEValueProtocolErrorIEContainerList(value), err
		}
		*s31.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.LocationReportIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s31.LocationReportIEContainer(value), fresh, budget)
		}
		*s31.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.LocationReportIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s31.LocationReportIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.LocationReportIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeLocationReportIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeLocationReportIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func RecommendedENBItemIEValueProtocolErrorIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable) s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := RecommendedENBItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.RecommendedENBItemIEValueProtocolErrorIEContainerList(value), err
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
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
func TAIItemIEValueProtocolErrorIEContainerListCodec(table s00.TAIItemIEValueIETable) TAIItemIEValueProtocolErrorIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TAIItemIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return TAIItemIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return TAIItemIEValueProtocolErrorIEContainerList(value), err
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
		f :=
			s.
				Begin()
		BridgeTAIItemIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
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
func KillRequestIEValueProtocolIEContainerListCodec(table s00.KillRequestIEValueIETable, bounds aper.ListBounds) s32.KillRequestIEValueProtocolIEContainerListValueCodec {
	codec := KillRequestIEValueIETableCodec(table, bounds)
	if *s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s32.KillRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s32.KillRequestIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s32.BridgeKillRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillRequestIEValueProtocolIEContainerList(value), err
		}
		*s32.BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillRequestIEContainerValueCodecFieldEncode(&codec))(s32.KillRequestIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s32.KillRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s32.BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func KillResponseIEValueProtocolIEContainerListCodec(table s00.KillResponseIEValueIETable, bounds aper.ListBounds) s32.KillResponseIEValueProtocolIEContainerListValueCodec {
	codec := KillResponseIEValueIETableCodec(table, bounds)
	if *s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.KillResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s32.KillResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s32.KillResponseIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.KillResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s32.BridgeKillResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.KillResponseIEValueProtocolIEContainerList(value), err
		}
		*s32.BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.KillResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeKillResponseIEContainerValueCodecFieldEncode(&codec))(s32.KillResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.KillResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s32.KillResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeKillResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s32.BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.KillResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeKillResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeKillResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func LocationReportIEValueProtocolIEContainerListCodec(table s00.LocationReportIEValueIETable, bounds aper.ListBounds) s31.LocationReportIEValueProtocolIEContainerListValueCodec {
	codec := LocationReportIEValueIETableCodec(table, bounds)
	if *s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.LocationReportIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s31.LocationReportIEValueProtocolIEContainerListValueCodec {
		sealed := s31.LocationReportIEValueProtocolIEContainerListValueCodec{}
		*s31.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.LocationReportIEValueProtocolIEContainerList, error) {
			value, err := (*s31.BridgeLocationReportIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.LocationReportIEValueProtocolIEContainerList(value), err
		}
		*s31.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.LocationReportIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeLocationReportIEContainerValueCodecFieldEncode(&codec))(s31.LocationReportIEContainer(value), fresh, budget)
		}
		*s31.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.LocationReportIEValueProtocolIEContainerList, options aper.DecodeState) (s31.LocationReportIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeLocationReportIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s31.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.LocationReportIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeLocationReportIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeLocationReportIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func RecommendedENBItemIEValueProtocolIEContainerListCodec(table s00.RecommendedENBItemIEValueIETable, bounds aper.ListBounds) s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec {
	codec := RecommendedENBItemIEValueIETableCodec(table, bounds)
	if *s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec {
		sealed := s32.RecommendedENBItemIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolIEContainerList, error) {
			value, err := (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.RecommendedENBItemIEValueProtocolIEContainerList(value), err
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.RecommendedENBItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeRecommendedENBItemIEContainerValueCodecFieldEncode(&codec))(s32.RecommendedENBItemIEContainer(value), fresh, budget)
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolIEContainerList, options aper.DecodeState) (s32.RecommendedENBItemIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s32.BridgeRecommendedENBItemIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.RecommendedENBItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
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
func TAIItemIEValueProtocolIEContainerListCodec(table s00.TAIItemIEValueIETable, bounds aper.ListBounds) TAIItemIEValueProtocolIEContainerListValueCodec {
	codec := TAIItemIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return TAIItemIEValueProtocolIEContainerListValueCodec{}
	}
	return TAIItemIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return TAIItemIEValueProtocolIEContainerList(value), err
	}, encode: func(value TAIItemIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TAIItemIEContainer(value), fresh, budget)
	}, capture: func(v TAIItemIEValueProtocolIEContainerList, options aper.DecodeState) (TAIItemIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTAIItemIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v TAIItemIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTAIItemIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// killRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[KillRequestIEValue].
type KillRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.KillRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.KillRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeKillRequestIEValueCaptureS1APProtocolIEField(v *s32.KillRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeKillRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeKillRequestIEFieldFieldReplay(v), *s32.BridgeKillRequestIEFieldFieldWithoutReplay(v))
}
func BridgeKillRequestIEValueCompareS1APProtocolIEField(v *s32.KillRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeKillRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeKillRequestIEFieldFieldReplay(v), *s32.BridgeKillRequestIEFieldFieldWithoutReplay(v))
}

// killResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[KillResponseIEValue].
type KillResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.KillResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.KillResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeKillResponseIEValueCaptureS1APProtocolIEField(v *s32.KillResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeKillResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeKillResponseIEFieldFieldReplay(v), *s32.BridgeKillResponseIEFieldFieldWithoutReplay(v))
}
func BridgeKillResponseIEValueCompareS1APProtocolIEField(v *s32.KillResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeKillResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeKillResponseIEFieldFieldReplay(v), *s32.BridgeKillResponseIEFieldFieldWithoutReplay(v))
}

// locationReportIEValueProtocolOpenValue is the concrete protocolOpenValue[LocationReportIEValue].
type LocationReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s31.LocationReportIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s31.LocationReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeLocationReportIEValueCaptureS1APProtocolIEField(v *s31.LocationReportIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s31.BridgeLocationReportIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s31.BridgeLocationReportIEFieldFieldReplay(v), *s31.BridgeLocationReportIEFieldFieldWithoutReplay(v))
}
func BridgeLocationReportIEValueCompareS1APProtocolIEField(v *s31.LocationReportIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s31.BridgeLocationReportIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s31.BridgeLocationReportIEFieldFieldReplay(v), *s31.BridgeLocationReportIEFieldFieldWithoutReplay(v))
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

func BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEField(v *s32.RecommendedENBItemIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeRecommendedENBItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeRecommendedENBItemIEFieldFieldReplay(v), *s32.BridgeRecommendedENBItemIEFieldFieldWithoutReplay(v))
}
func BridgeRecommendedENBItemIEValueCompareS1APProtocolIEField(v *s32.RecommendedENBItemIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeRecommendedENBItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeRecommendedENBItemIEFieldFieldReplay(v), *s32.BridgeRecommendedENBItemIEFieldFieldWithoutReplay(v))
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

// KillRequestAPERValue is the concrete APERValue[KillRequest].
type KillRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   KillRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillRequestAPERValue) WithoutReplay() KillRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillResponseAPERValue is the concrete APERValue[KillResponse].
type KillResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   KillResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillResponseAPERValue) WithoutReplay() KillResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LocationReportAPERValue is the concrete APERValue[LocationReport].
type LocationReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   LocationReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LocationReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LocationReportAPERValue) WithoutReplay() LocationReportAPERValue {
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
	Value   RecommendedENBsForPaging

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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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

// ENBDirectInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ENBDirectInformationTransferIEValue]].
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

// ENBDirectInformationTransferIEValueERABIEContainerList is the concrete ERABIEContainerList[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueERABIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APERABIEContainerList(v *s32.KillRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APERABIEContainerList(v *s32.KillRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeKillResponseIEValueCaptureS1APERABIEContainerList(v *s32.KillResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APERABIEContainerList(v *s32.KillResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APERABIEContainerList(v *s31.LocationReportIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APERABIEContainerList(v *s31.LocationReportIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEDirectInformationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[MMEDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueERABIEContainerList is the concrete ERABIEContainerList[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueERABIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeRecommendedENBItemIEValueCaptureS1APERABIEContainerList(v *s32.RecommendedENBItemIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
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
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[TAIItemIEValue]].
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

// TAIItemIEValueERABIEContainerList is the concrete ERABIEContainerList[TAIItemIEValue].
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

// WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueERABIEContainerList, error)
	encode  func(WriteReplaceWarningRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequestIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) New(value WriteReplaceWarningRequestIEValueERABIEContainerList) (WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningRequestIEValueERABIEContainerList is the concrete ERABIEContainerList[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueERABIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// ENBDirectInformationTransferIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[MMEDirectInformationTransferIEValue]].
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

// TAIItemIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEField, error)
	encode  func(WriteReplaceWarningRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequestIEField, aper.DecodeState) (WriteReplaceWarningRequestIEField, aper.Snapshot)
	compare func(WriteReplaceWarningRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestIEFieldValueCodec) New(value WriteReplaceWarningRequestIEField) (WriteReplaceWarningRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestIEFieldValueCodec) EncodeAPER(value WriteReplaceWarningRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WriteReplaceWarningRequestIEFieldValueCodec) encodeBudgetValue(value WriteReplaceWarningRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestIEFieldValueCodec) encodeChanged(value WriteReplaceWarningRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[MMEDirectInformationTransferIEValue]].
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
func BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEContainer(v *s32.RecommendedENBItemIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeRecommendedENBItemIEValueCompareS1APProtocolIEContainer(v *s32.RecommendedENBItemIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEContainer, error)
	encode  func(WriteReplaceWarningRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequestIEContainer, aper.DecodeState) (WriteReplaceWarningRequestIEContainer, aper.Snapshot)
	compare func(WriteReplaceWarningRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestIEContainerValueCodec) New(value WriteReplaceWarningRequestIEContainer) (WriteReplaceWarningRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestIEContainerValueCodec) EncodeAPER(value WriteReplaceWarningRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WriteReplaceWarningRequestIEContainerValueCodec) encodeBudgetValue(value WriteReplaceWarningRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestIEContainerValueCodec) encodeChanged(value WriteReplaceWarningRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ENBDirectInformationTransferIEValue]].
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

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueProtocolErrorIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.KillRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s32.KillRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeKillResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.KillResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s32.KillResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APProtocolErrorIEContainerList(v *s31.LocationReportIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APProtocolErrorIEContainerList(v *s31.LocationReportIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[MMEDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueProtocolErrorIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeRecommendedENBItemIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.RecommendedENBItemIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
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
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[TAIItemIEValue]].
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

// TAIItemIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[TAIItemIEValue].
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

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) New(value WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// ENBDirectInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ENBDirectInformationTransferIEValue]].
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

// ENBDirectInformationTransferIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueProtocolIEContainerList []ENBDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeKillRequestIEValueCaptureS1APProtocolIEContainerList(v *s32.KillRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APProtocolIEContainerList(v *s32.KillRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeKillResponseIEValueCaptureS1APProtocolIEContainerList(v *s32.KillResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APProtocolIEContainerList(v *s32.KillResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeKillResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APProtocolIEContainerList(v *s31.LocationReportIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APProtocolIEContainerList(v *s31.LocationReportIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeLocationReportIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// MMEDirectInformationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[MMEDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueProtocolIEContainerList []MMEDirectInformationTransferIEValueProtocolIESingleContainer

func BridgeRecommendedENBItemIEValueCaptureS1APProtocolIEContainerList(v *s32.RecommendedENBItemIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
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
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TAIItemIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[TAIItemIEValue]].
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

// TAIItemIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[TAIItemIEValue].
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

// WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolIEContainerList, error)
	encode  func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) New(value WriteReplaceWarningRequestIEValueProtocolIEContainerList) (WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value WriteReplaceWarningRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value WriteReplaceWarningRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningRequestIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueProtocolIEContainerList []WriteReplaceWarningRequestIEValueProtocolIESingleContainer

// ENBDirectInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ENBDirectInformationTransferIEValue]].
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

// ENBDirectInformationTransferIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ENBDirectInformationTransferIEValue].
type ENBDirectInformationTransferIEValueProtocolIESingleContainer = ENBDirectInformationTransferIEField

func BridgeKillRequestIEValueCaptureS1APProtocolIESingleContainer(v *s32.KillRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeKillRequestIEValueCompareS1APProtocolIESingleContainer(v *s32.KillRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeKillResponseIEValueCaptureS1APProtocolIESingleContainer(v *s32.KillResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeKillResponseIEValueCompareS1APProtocolIESingleContainer(v *s32.KillResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeLocationReportIEValueCaptureS1APProtocolIESingleContainer(v *s31.LocationReportIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeLocationReportIEValueCompareS1APProtocolIESingleContainer(v *s31.LocationReportIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// MMEDirectInformationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[MMEDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MMEDirectInformationTransferIEValue].
type MMEDirectInformationTransferIEValueProtocolIESingleContainer = MMEDirectInformationTransferIEField

// TAIItemIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueProtocolIESingleContainer = WriteReplaceWarningRequestIEField

// ENBDirectInformationTransferIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEFieldAPERValue is the concrete APERValue[ProtocolIEField[MMEDirectInformationTransferIEValue]].
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

// TAIItemIEFieldAPERValue is the concrete APERValue[ProtocolIEField[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEFieldAPERValue is the concrete APERValue[ProtocolIEField[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEFieldAPERValue) WithoutReplay() WriteReplaceWarningRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[MMEDirectInformationTransferIEValue]].
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

// TAIItemIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEContainerAPERValue) WithoutReplay() WriteReplaceWarningRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[MMEDirectInformationTransferIEValue]].
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

// TAIItemIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBDirectInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ENBDirectInformationTransferIEValue]].
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

// MMEDirectInformationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[MMEDirectInformationTransferIEValue]].
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

// TAIItemIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[TAIItemIEValue]].
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

// WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[WriteReplaceWarningRequestIEValue]].
type WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         WriteReplaceWarningRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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
func BridgeCaptureS1APInformationOnRecommendedCellsAndENBsForPaging(v *InformationOnRecommendedCellsAndENBsForPaging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s26.BridgeCaptureS1APRecommendedCellsForPaging(&v.RecommendedCellsForPaging, s)
	BridgeCaptureS1APRecommendedENBsForPaging(&v.RecommendENBsForPaging, s)
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
	BridgeCompareS1APRecommendedENBsForPaging(&v.RecommendENBsForPaging, s)
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
func BridgeCaptureS1APKillRequest(v *KillRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APKillRequest(v *KillRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APKillResponse(v *KillResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APKillResponse(v *KillResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeKillResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APLocationReport(v *LocationReport, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APLocationReport(v *LocationReport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeLocationReportIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
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
func BridgeCaptureS1APRecommendedENBList(v *s32.RecommendedENBList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareS1APRecommendedENBList(v *s32.RecommendedENBList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeRecommendedENBItemIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APRecommendedENBsForPaging(v *RecommendedENBsForPaging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCaptureS1APRecommendedENBList(&v.RecommendedENBList, s)
	s.Bool(v.IEExtensions == nil)
	s26.BridgeRecommendedENBsForPagingExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APRecommendedENBsForPaging(v *RecommendedENBsForPaging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APRecommendedENBList(&v.RecommendedENBList, s)
	s.Bool(v.IEExtensions == nil)
	s26.BridgeRecommendedENBsForPagingExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTAIItem(v *TAIItem, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s31.BridgeCaptureS1APTAI(&v.TAI, s)
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
	s31.BridgeCompareS1APTAI(&v.TAI, s)
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
func BridgeCaptureS1APWriteReplaceWarningRequestIEValue(v *WriteReplaceWarningRequestIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s00.BridgeCaptureS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s00.BridgeCaptureS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(113):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaList == nil)
				if v.rowWarningAreaList != nil {
					s32.BridgeCaptureS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(114):
			{
				f := s.Begin()
				s.Bool(v.rowRepetitionPeriod == nil)
				if v.rowRepetitionPeriod != nil {
					s00.BridgeCaptureS1APRepetitionPeriod(v.rowRepetitionPeriod, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(144):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedRepetitionPeriod == nil)
				if v.rowExtendedRepetitionPeriod != nil {
					s00.BridgeCaptureS1APExtendedRepetitionPeriod(v.rowExtendedRepetitionPeriod, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(115):
			{
				f := s.Begin()
				s.Bool(v.rowNumberofBroadcastRequest == nil)
				if v.rowNumberofBroadcastRequest != nil {
					s00.BridgeCaptureS1APNumberofBroadcastRequest(v.rowNumberofBroadcastRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(116):
			{
				f := s.Begin()
				s.Bool(v.rowWarningType == nil)
				if v.rowWarningType != nil {
					s00.BridgeCaptureS1APWarningType(v.rowWarningType, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(117):
			{
				f := s.Begin()
				s.Bool(v.rowWarningSecurityInfo == nil)
				if v.rowWarningSecurityInfo != nil {
					s00.BridgeCaptureS1APWarningSecurityInfo(v.rowWarningSecurityInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(118):
			{
				f := s.Begin()
				s.Bool(v.rowDataCodingScheme == nil)
				if v.rowDataCodingScheme != nil {
					s00.BridgeCaptureS1APDataCodingScheme(v.rowDataCodingScheme, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(119):
			{
				f := s.Begin()
				s.Bool(v.rowWarningMessageContents == nil)
				if v.rowWarningMessageContents != nil {
					s00.BridgeCaptureS1APWarningMessageContents(v.rowWarningMessageContents, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(142):
			{
				f := s.Begin()
				s.Bool(v.rowConcurrentWarningMessageIndicator == nil)
				if v.rowConcurrentWarningMessageIndicator != nil {
					s00.BridgeCaptureS1APConcurrentWarningMessageIndicator(v.rowConcurrentWarningMessageIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(286):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaCoordinates == nil)
				if v.rowWarningAreaCoordinates != nil {
					s00.BridgeCaptureS1APWarningAreaCoordinates(v.rowWarningAreaCoordinates, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WriteReplaceWarningRequestIEValue) captureSemantics(s aper.SemanticCapture) WriteReplaceWarningRequestIEValue {
	BridgeCaptureS1APWriteReplaceWarningRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APWriteReplaceWarningRequestIEValue(v *WriteReplaceWarningRequestIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(111):
			{
				f := s.Begin()
				s.Bool(v.rowMessageIdentifier == nil)
				if v.rowMessageIdentifier != nil {
					s02.BridgeCompareS1APMessageIdentifier(v.rowMessageIdentifier, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(112):
			{
				f := s.Begin()
				s.Bool(v.rowSerialNumber == nil)
				if v.rowSerialNumber != nil {
					s07.BridgeCompareS1APSerialNumber(v.rowSerialNumber, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(113):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaList == nil)
				if v.rowWarningAreaList != nil {
					s32.BridgeCompareS1APWarningAreaList(v.rowWarningAreaList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(114):
			{
				f := s.Begin()
				s.Bool(v.rowRepetitionPeriod == nil)
				if v.rowRepetitionPeriod != nil {
					s06.BridgeCompareS1APRepetitionPeriod(v.rowRepetitionPeriod, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(144):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedRepetitionPeriod == nil)
				if v.rowExtendedRepetitionPeriod != nil {
					s02.BridgeCompareS1APExtendedRepetitionPeriod(v.rowExtendedRepetitionPeriod, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(115):
			{
				f := s.Begin()
				s.Bool(v.rowNumberofBroadcastRequest == nil)
				if v.rowNumberofBroadcastRequest != nil {
					s02.BridgeCompareS1APNumberofBroadcastRequest(v.rowNumberofBroadcastRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(116):
			{
				f := s.Begin()
				s.Bool(v.rowWarningType == nil)
				if v.rowWarningType != nil {
					s07.BridgeCompareS1APWarningType(v.rowWarningType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(117):
			{
				f := s.Begin()
				s.Bool(v.rowWarningSecurityInfo == nil)
				if v.rowWarningSecurityInfo != nil {
					s07.BridgeCompareS1APWarningSecurityInfo(v.rowWarningSecurityInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(118):
			{
				f := s.Begin()
				s.Bool(v.rowDataCodingScheme == nil)
				if v.rowDataCodingScheme != nil {
					s02.BridgeCompareS1APDataCodingScheme(v.rowDataCodingScheme, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(119):
			{
				f := s.Begin()
				s.Bool(v.rowWarningMessageContents == nil)
				if v.rowWarningMessageContents != nil {
					s07.BridgeCompareS1APWarningMessageContents(v.rowWarningMessageContents, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(142):
			{
				f := s.Begin()
				s.Bool(v.rowConcurrentWarningMessageIndicator == nil)
				if v.rowConcurrentWarningMessageIndicator != nil {
					s02.BridgeCompareS1APConcurrentWarningMessageIndicator(v.rowConcurrentWarningMessageIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(286):
			{
				f := s.Begin()
				s.Bool(v.rowWarningAreaCoordinates == nil)
				if v.rowWarningAreaCoordinates != nil {
					s07.BridgeCompareS1APWarningAreaCoordinates(v.rowWarningAreaCoordinates, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v WriteReplaceWarningRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APWriteReplaceWarningRequestIEValue(&v, &s)
	return s
}

// NewAreaScopeOfMDTCellBased creates a AreaScopeOfMDT with the cellBased alternative.
func BridgeNewAreaScopeOfMDTCellBasedLegacy(v s22.CellBasedMDT) s32.AreaScopeOfMDT {
	return s32.AreaScopeOfMDT{
		Choice:    s00.AreaScopeOfMDTChoiceCellBased,
		CellBased: &v,
	}
}

// NewAreaScopeOfMDTTABased creates a AreaScopeOfMDT with the tABased alternative.
func BridgeNewAreaScopeOfMDTTABasedLegacy(v s31.TABasedMDT) s32.AreaScopeOfMDT {
	return s32.AreaScopeOfMDT{
		Choice:  s00.AreaScopeOfMDTChoiceTABased,
		TABased: &v,
	}
}

// NewAreaScopeOfMDTPLMNWide creates a AreaScopeOfMDT with the pLMNWide alternative.
func BridgeNewAreaScopeOfMDTPLMNWideLegacy(v struct{}) s32.AreaScopeOfMDT {
	return s32.AreaScopeOfMDT{
		Choice:   s00.AreaScopeOfMDTChoicePLMNWide,
		PLMNWide: &v,
	}
}

// NewAreaScopeOfMDTTAIBased creates a AreaScopeOfMDT with the tAIBased alternative.
func BridgeNewAreaScopeOfMDTTAIBasedLegacy(v s32.TAIBasedMDT) s32.AreaScopeOfMDT {
	return s32.AreaScopeOfMDT{
		Choice:   s00.AreaScopeOfMDTChoiceTAIBased,
		TAIBased: &v,
	}
}

// NewAreaScopeOfQMCCellBased creates a AreaScopeOfQMC with the cellBased alternative.
func BridgeNewAreaScopeOfQMCCellBasedLegacy(v s22.CellBasedQMC) s32.AreaScopeOfQMC {
	return s32.AreaScopeOfQMC{
		Choice:    s00.AreaScopeOfQMCChoiceCellBased,
		CellBased: &v,
	}
}

// NewAreaScopeOfQMCTABased creates a AreaScopeOfQMC with the tABased alternative.
func BridgeNewAreaScopeOfQMCTABasedLegacy(v s31.TABasedQMC) s32.AreaScopeOfQMC {
	return s32.AreaScopeOfQMC{
		Choice:  s00.AreaScopeOfQMCChoiceTABased,
		TABased: &v,
	}
}

// NewAreaScopeOfQMCTAIBased creates a AreaScopeOfQMC with the tAIBased alternative.
func BridgeNewAreaScopeOfQMCTAIBasedLegacy(v s32.TAIBasedQMC) s32.AreaScopeOfQMC {
	return s32.AreaScopeOfQMC{
		Choice:   s00.AreaScopeOfQMCChoiceTAIBased,
		TAIBased: &v,
	}
}

// NewAreaScopeOfQMCPLMNAreaBased creates a AreaScopeOfQMC with the pLMNAreaBased alternative.
func BridgeNewAreaScopeOfQMCPLMNAreaBasedLegacy(v s20.PLMNAreaBasedQMC) s32.AreaScopeOfQMC {
	return s32.AreaScopeOfQMC{
		Choice:        s00.AreaScopeOfQMCChoicePLMNAreaBased,
		PLMNAreaBased: &v,
	}
}

// NewBroadcastCancelledAreaListCellIDCancelled creates a BroadcastCancelledAreaList with the cellID-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListCellIDCancelledLegacy(v s17.CellIDCancelled) s32.BroadcastCancelledAreaList {
	return s32.BroadcastCancelledAreaList{
		Choice:          s00.BroadcastCancelledAreaListChoiceCellIDCancelled,
		CellIDCancelled: v,
	}
}

// NewBroadcastCancelledAreaListTAICancelled creates a BroadcastCancelledAreaList with the tAI-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListTAICancelledLegacy(v s32.TAICancelled) s32.BroadcastCancelledAreaList {
	return s32.BroadcastCancelledAreaList{
		Choice:       s00.BroadcastCancelledAreaListChoiceTAICancelled,
		TAICancelled: v,
	}
}

// NewBroadcastCancelledAreaListEmergencyAreaIDCancelled creates a BroadcastCancelledAreaList with the emergencyAreaID-Cancelled alternative.
func BridgeNewBroadcastCancelledAreaListEmergencyAreaIDCancelledLegacy(v s22.EmergencyAreaIDCancelled) s32.BroadcastCancelledAreaList {
	return s32.BroadcastCancelledAreaList{
		Choice:                   s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled,
		EmergencyAreaIDCancelled: v,
	}
}

// NewBroadcastCompletedAreaListCellIDBroadcast creates a BroadcastCompletedAreaList with the cellID-Broadcast alternative.
func BridgeNewBroadcastCompletedAreaListCellIDBroadcastLegacy(v s17.CellIDBroadcast) s32.BroadcastCompletedAreaList {
	return s32.BroadcastCompletedAreaList{
		Choice:          s00.BroadcastCompletedAreaListChoiceCellIDBroadcast,
		CellIDBroadcast: v,
	}
}

// NewBroadcastCompletedAreaListTAIBroadcast creates a BroadcastCompletedAreaList with the tAI-Broadcast alternative.
func BridgeNewBroadcastCompletedAreaListTAIBroadcastLegacy(v s32.TAIBroadcast) s32.BroadcastCompletedAreaList {
	return s32.BroadcastCompletedAreaList{
		Choice:       s00.BroadcastCompletedAreaListChoiceTAIBroadcast,
		TAIBroadcast: v,
	}
}

// NewBroadcastCompletedAreaListEmergencyAreaIDBroadcast creates a BroadcastCompletedAreaList with the emergencyAreaID-Broadcast alternative.
func BridgeNewBroadcastCompletedAreaListEmergencyAreaIDBroadcastLegacy(v s22.EmergencyAreaIDBroadcast) s32.BroadcastCompletedAreaList {
	return s32.BroadcastCompletedAreaList{
		Choice:                   s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast,
		EmergencyAreaIDBroadcast: v,
	}
}

// NewENDCSONTransferTypeRequest creates a ENDCSONTransferType with the request alternative.
func BridgeNewENDCSONTransferTypeRequestLegacy(v s31.ENDCTransferTypeRequest) s31.ENDCSONTransferType {
	return s31.ENDCSONTransferType{
		Choice:  s00.ENDCSONTransferTypeChoiceRequest,
		Request: &v,
	}
}

// NewENDCSONTransferTypeReply creates a ENDCSONTransferType with the reply alternative.
func BridgeNewENDCSONTransferTypeReplyLegacy(v s31.ENDCTransferTypeReply) s31.ENDCSONTransferType {
	return s31.ENDCSONTransferType{
		Choice: s00.ENDCSONTransferTypeChoiceReply,
		Reply:  &v,
	}
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
	RecommendENBsForPaging    RecommendedENBsForPaging                                            `asn1:"tag:1,context,implicit"`
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

// NewMMEPagingTargetGlobalENBID creates a MMEPagingTarget with the global-ENB-ID alternative.
func BridgeNewMMEPagingTargetGlobalENBIDLegacy(v s18.GlobalENBID) s31.MMEPagingTarget {
	return s31.MMEPagingTarget{
		Choice:      s00.MMEPagingTargetChoiceGlobalENBID,
		GlobalENBID: &v,
	}
}

// NewMMEPagingTargetTAI creates a MMEPagingTarget with the tAI alternative.
func BridgeNewMMEPagingTargetTAILegacy(v s31.TAI) s31.MMEPagingTarget {
	return s31.MMEPagingTarget{
		Choice: s00.MMEPagingTargetChoiceTAI,
		TAI:    &v,
	}
}

// RecommendedENBsForPaging represents the ASN.1 type RecommendedENBsForPaging (SEQUENCE).
type RecommendedENBsForPaging struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	RecommendedENBList      s32.RecommendedENBList                         `asn1:"tag:0,context,implicit"`
	recommendedENBListIndef bool                                           `asn1:"-" json:"-"`
	IEExtensions            s11.RecommendedENBsForPagingExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef       bool                                           `asn1:"-" json:"-"`
	extCount                int64                                          `asn1:"-" json:"-"`
	extPresent              []bool                                         `asn1:"-" json:"-"`
	extData                 [][]byte                                       `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
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

// NewWarningAreaListCellIDList creates a WarningAreaList with the cellIDList alternative.
func BridgeNewWarningAreaListCellIDListLegacy(v s17.ECGIList) s32.WarningAreaList {
	return s32.WarningAreaList{
		Choice:     s00.WarningAreaListChoiceCellIDList,
		CellIDList: v,
	}
}

// NewWarningAreaListTrackingAreaListforWarning creates a WarningAreaList with the trackingAreaListforWarning alternative.
func BridgeNewWarningAreaListTrackingAreaListforWarningLegacy(v s32.TAIListforWarning) s32.WarningAreaList {
	return s32.WarningAreaList{
		Choice:                     s00.WarningAreaListChoiceTrackingAreaListforWarning,
		TrackingAreaListforWarning: v,
	}
}

// NewWarningAreaListEmergencyAreaIDList creates a WarningAreaList with the emergencyAreaIDList alternative.
func BridgeNewWarningAreaListEmergencyAreaIDListLegacy(v s00.EmergencyAreaIDList) s32.WarningAreaList {
	return s32.WarningAreaList{
		Choice:              s00.WarningAreaListChoiceEmergencyAreaIDList,
		EmergencyAreaIDList: v,
	}
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
	if err := v.RecommendENBsForPaging.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	if err := v.RecommendENBsForPaging.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendENBsForPaging")
	}
	bb.LeaveComponent(toleranceMark_recommendenbsforpaging)
	if opt_ieextensions {
		tmp_ieextensions := make(s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.InformationOnRecommendedCellsAndENBsForPagingExtIEsExtField
				if err := s09.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RecommendedENBsForPaging to APER format.
func (v *RecommendedENBsForPaging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RecommendedENBsForPaging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.RecommendedENBList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedenblist, fragmentLength_recommendedenblist int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_recommendedenblist < 0 || fragmentOffset_recommendedenblist > int64(len(v.RecommendedENBList)) || fragmentLength_recommendedenblist < 0 || fragmentLength_recommendedenblist > int64(len(v.RecommendedENBList[fragmentOffset_recommendedenblist:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.RecommendedENBList[fragmentOffset_recommendedenblist : fragmentOffset_recommendedenblist+fragmentLength_recommendedenblist] {
			if err := s32.BridgeRecommendedENBItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding recommendedENBList element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding recommendedENBList: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes RecommendedENBsForPaging from APER format.
func (v *RecommendedENBsForPaging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RecommendedENBsForPaging with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RecommendedENBsForPaging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBsForPaging")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBsForPaging")
	}
	padding, err := aper.CaptureFinalBits(bb, "RecommendedENBsForPaging")
	if err != nil {
		return runtime.WrapDecodePath(err, "RecommendedENBsForPaging")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RecommendedENBsForPaging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RecommendedENBsForPaging{}
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
	v.RecommendedENBList = make(s32.RecommendedENBList, 0)
	_, errCollection_recommendedenblist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_recommendedenblist, fragmentLength_recommendedenblist int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_recommendedenblist < 0 || fragmentLength_recommendedenblist < 0 || fragmentLength_recommendedenblist > int64(^uint(0)>>1) || fragmentOffset_recommendedenblist > int64(^uint(0)>>1)-fragmentLength_recommendedenblist {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_recommendedenblist; i++ {
			var elem s32.RecommendedENBItemIEValueProtocolIESingleContainer
			if err := s32.BridgeRecommendedENBItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBList[%d]", fragmentOffset_recommendedenblist+i))
			}
			if next, err := aper.AppendValues(bb, v.RecommendedENBList, elem); err != nil {
				return err
			} else {
				v.RecommendedENBList = next
			}
		}
		return nil
	})
	if errCollection_recommendedenblist != nil {
		return runtime.WrapDecodePath(errCollection_recommendedenblist, "RecommendedENBList")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s11.RecommendedENBsForPagingExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.RecommendedENBsForPagingExtIEsExtField
				if err := s11.BridgeRecommendedENBsForPagingExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERRecommendedENBListTo appends a RecommendedENBList list to bb.
func BridgeMarshalAPERRecommendedENBListTo(list s32.RecommendedENBList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERRecommendedENBListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s32.BridgeRecommendedENBItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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
		tmp_ieextensions := make(s10.RIMTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s10.RIMTransferExtIEsExtField
				if err := s10.BridgeRIMTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			recoveryMark_targetrncid := inner.RecoveryComponent("TargetRNCID")
			var dec_targetrncid TargetRNCID
			if err := dec_targetrncid.unmarshalAPERFrom(inner); err != nil {
				return runtime.WrapDecodePath(err, "TargetRNCID")
			}
			if err := aper.ChargeValue(inner, dec_targetrncid); err != nil {
				return err
			}
			v.TargetRNCID = &dec_targetrncid
			inner.LeaveComponent(recoveryMark_targetrncid)
		case s00.RIMRoutingAddressChoiceEHRPDSectorID:
			extensionPath = "EHRPDSectorID"
			val_ehrpdsectorid, err := aper.DecodeOctetStringAligned(inner, 16, 16, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "EHRPDSectorID")
			}
			tmp_ehrpdsectorid := val_ehrpdsectorid
			v.EHRPDSectorID = tmp_ehrpdsectorid
		}
		padding, err := aper.CaptureOpenTypePadding(inner)
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

// MarshalAPERTAIListforMDTTo appends a TAIListforMDT list to bb.
func BridgeMarshalAPERTAIListforMDTTo(list s32.TAIListforMDT, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAIListforMDTListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s31.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAIListforWarningTo appends a TAIListforWarning list to bb.
func BridgeMarshalAPERTAIListforWarningTo(list s32.TAIListforWarning, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAIListforWarningListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s31.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAIBroadcastTo appends a TAIBroadcast list to bb.
func BridgeMarshalAPERTAIBroadcastTo(list s32.TAIBroadcast, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAIBroadcastListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s32.BridgeTAIBroadcastItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAICancelledTo appends a TAICancelled list to bb.
func BridgeMarshalAPERTAICancelledTo(list s32.TAICancelled, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAICancelledListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s32.BridgeTAICancelledItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERTAIListforQMCTo appends a TAIListforQMC list to bb.
func BridgeMarshalAPERTAIListforQMCTo(list s32.TAIListforQMC, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAIListforQMCListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s31.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
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
		tmp_ieextensions := make(s11.TargetRNCIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargetRNCIDExtIEsExtField
				if err := s11.BridgeTargetRNCIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		tmp_ieextensions := make(s11.TargetNgRanNodeIDExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TargetNgRanNodeIDExtIEsExtField
				if err := s11.BridgeTargetNgRanNodeIDExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPERTAIListForRestartTo appends a TAIListForRestart list to bb.
func BridgeMarshalAPERTAIListForRestartTo(list s32.TAIListForRestart, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s32.BridgeAsn1cAPERTAIListForRestartListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2048, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s31.BridgeTAIMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
func (v *RecommendedENBsForPaging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "RecommendedENBsForPaging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RecommendedENBsForPaging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RecommendedENBsForPaging) WithoutReplay() RecommendedENBsForPaging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RecommendedENBsForPaging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
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
func (v *RecommendedENBsForPaging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RecommendedENBsForPaging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedENBsForPaging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBsForPaging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RecommendedENBsForPaging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RecommendedENBsForPaging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RecommendedENBsForPaging.Extensions[%d]", index))
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
func (v *RecommendedENBsForPaging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RecommendedENBsForPaging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *RecommendedENBsForPaging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBsForPaging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APRecommendedENBsForPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "RecommendedENBsForPaging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "RecommendedENBsForPaging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *RecommendedENBsForPaging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "RecommendedENBsForPaging")
}
func (v *RecommendedENBsForPaging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "RecommendedENBsForPaging")
}
func (v *RecommendedENBsForPaging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APRecommendedENBsForPaging(v, &s)
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
func (v *RecommendedENBsForPaging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *RecommendedENBsForPaging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *RecommendedENBsForPaging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RecommendedENBsForPaging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded RecommendedENBsForPaging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APRecommendedENBsForPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = RecommendedENBsForPaging{}
		return report, aper.OperationError(err, "RecommendedENBsForPaging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RecommendedENBsForPaging")
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

// NewAreaScopeOfMDTCellBased constructs a checked complete value.
func NewAreaScopeOfMDTCellBased(v s22.CellBasedMDT, options ...aper.BuildOption) (s32.AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	value := BridgeNewAreaScopeOfMDTCellBasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTCellBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTCellBased")
}

// NewAreaScopeOfMDTTABased constructs a checked complete value.
func NewAreaScopeOfMDTTABased(v s31.TABasedMDT, options ...aper.BuildOption) (s32.AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	value := BridgeNewAreaScopeOfMDTTABasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTABased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTTABased")
}

// NewAreaScopeOfMDTPLMNWide constructs a checked complete value.
func NewAreaScopeOfMDTPLMNWide(v struct{}, options ...aper.BuildOption) (s32.AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	value := BridgeNewAreaScopeOfMDTPLMNWideLegacy(v)
	if _, err := s32.BridgeAreaScopeOfMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTPLMNWide")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTPLMNWide")
}

// NewAreaScopeOfMDTTAIBased constructs a checked complete value.
func NewAreaScopeOfMDTTAIBased(v s32.TAIBasedMDT, options ...aper.BuildOption) (s32.AreaScopeOfMDT, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	value := BridgeNewAreaScopeOfMDTTAIBasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfMDTMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfMDT{}, aper.OperationError(err, "AreaScopeOfMDTTAIBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfMDTTAIBased")
}

// NewAreaScopeOfQMCCellBased constructs a checked complete value.
func NewAreaScopeOfQMCCellBased(v s22.CellBasedQMC, options ...aper.BuildOption) (s32.AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	value := BridgeNewAreaScopeOfQMCCellBasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfQMCMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCCellBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCCellBased")
}

// NewAreaScopeOfQMCTABased constructs a checked complete value.
func NewAreaScopeOfQMCTABased(v s31.TABasedQMC, options ...aper.BuildOption) (s32.AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	value := BridgeNewAreaScopeOfQMCTABasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfQMCMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTABased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCTABased")
}

// NewAreaScopeOfQMCTAIBased constructs a checked complete value.
func NewAreaScopeOfQMCTAIBased(v s32.TAIBasedQMC, options ...aper.BuildOption) (s32.AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	value := BridgeNewAreaScopeOfQMCTAIBasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfQMCMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCTAIBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCTAIBased")
}

// NewAreaScopeOfQMCPLMNAreaBased constructs a checked complete value.
func NewAreaScopeOfQMCPLMNAreaBased(v s20.PLMNAreaBasedQMC, options ...aper.BuildOption) (s32.AreaScopeOfQMC, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	value := BridgeNewAreaScopeOfQMCPLMNAreaBasedLegacy(v)
	if _, err := s32.BridgeAreaScopeOfQMCMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.AreaScopeOfQMC{}, aper.OperationError(err, "AreaScopeOfQMCPLMNAreaBased")
	}
	return value, aper.OperationError(nil, "AreaScopeOfQMCPLMNAreaBased")
}

// NewBroadcastCancelledAreaListCellIDCancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListCellIDCancelled(v s17.CellIDCancelled, options ...aper.BuildOption) (s32.BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListCellIDCancelledLegacy(v)
	if _, err := s32.BridgeBroadcastCancelledAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListCellIDCancelled")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListCellIDCancelled")
}

// NewBroadcastCancelledAreaListTAICancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListTAICancelled(v s32.TAICancelled, options ...aper.BuildOption) (s32.BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListTAICancelledLegacy(v)
	if _, err := s32.BridgeBroadcastCancelledAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListTAICancelled")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListTAICancelled")
}

// NewBroadcastCancelledAreaListEmergencyAreaIDCancelled constructs a checked complete value.
func NewBroadcastCancelledAreaListEmergencyAreaIDCancelled(v s22.EmergencyAreaIDCancelled, options ...aper.BuildOption) (s32.BroadcastCancelledAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
	}
	value := BridgeNewBroadcastCancelledAreaListEmergencyAreaIDCancelledLegacy(v)
	if _, err := s32.BridgeBroadcastCancelledAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCancelledAreaList{}, aper.OperationError(err, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
	}
	return value, aper.OperationError(nil, "BroadcastCancelledAreaListEmergencyAreaIDCancelled")
}

// NewBroadcastCompletedAreaListCellIDBroadcast constructs a checked complete value.
func NewBroadcastCompletedAreaListCellIDBroadcast(v s17.CellIDBroadcast, options ...aper.BuildOption) (s32.BroadcastCompletedAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListCellIDBroadcast")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListCellIDBroadcast")
	}
	value := BridgeNewBroadcastCompletedAreaListCellIDBroadcastLegacy(v)
	if _, err := s32.BridgeBroadcastCompletedAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListCellIDBroadcast")
	}
	return value, aper.OperationError(nil, "BroadcastCompletedAreaListCellIDBroadcast")
}

// NewBroadcastCompletedAreaListTAIBroadcast constructs a checked complete value.
func NewBroadcastCompletedAreaListTAIBroadcast(v s32.TAIBroadcast, options ...aper.BuildOption) (s32.BroadcastCompletedAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListTAIBroadcast")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListTAIBroadcast")
	}
	value := BridgeNewBroadcastCompletedAreaListTAIBroadcastLegacy(v)
	if _, err := s32.BridgeBroadcastCompletedAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListTAIBroadcast")
	}
	return value, aper.OperationError(nil, "BroadcastCompletedAreaListTAIBroadcast")
}

// NewBroadcastCompletedAreaListEmergencyAreaIDBroadcast constructs a checked complete value.
func NewBroadcastCompletedAreaListEmergencyAreaIDBroadcast(v s22.EmergencyAreaIDBroadcast, options ...aper.BuildOption) (s32.BroadcastCompletedAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListEmergencyAreaIDBroadcast")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListEmergencyAreaIDBroadcast")
	}
	value := BridgeNewBroadcastCompletedAreaListEmergencyAreaIDBroadcastLegacy(v)
	if _, err := s32.BridgeBroadcastCompletedAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.BroadcastCompletedAreaList{}, aper.OperationError(err, "BroadcastCompletedAreaListEmergencyAreaIDBroadcast")
	}
	return value, aper.OperationError(nil, "BroadcastCompletedAreaListEmergencyAreaIDBroadcast")
}

// NewENDCSONTransferTypeRequest constructs a checked complete value.
func NewENDCSONTransferTypeRequest(v s31.ENDCTransferTypeRequest, options ...aper.BuildOption) (s31.ENDCSONTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	value := BridgeNewENDCSONTransferTypeRequestLegacy(v)
	if _, err := s31.BridgeENDCSONTransferTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeRequest")
	}
	return value, aper.OperationError(nil, "ENDCSONTransferTypeRequest")
}

// NewENDCSONTransferTypeReply constructs a checked complete value.
func NewENDCSONTransferTypeReply(v s31.ENDCTransferTypeReply, options ...aper.BuildOption) (s31.ENDCSONTransferType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	value := BridgeNewENDCSONTransferTypeReplyLegacy(v)
	if _, err := s31.BridgeENDCSONTransferTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s31.ENDCSONTransferType{}, aper.OperationError(err, "ENDCSONTransferTypeReply")
	}
	return value, aper.OperationError(nil, "ENDCSONTransferTypeReply")
}

// NewMMEPagingTargetGlobalENBID constructs a checked complete value.
func NewMMEPagingTargetGlobalENBID(v s18.GlobalENBID, options ...aper.BuildOption) (s31.MMEPagingTarget, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	value := BridgeNewMMEPagingTargetGlobalENBIDLegacy(v)
	if _, err := s31.BridgeMMEPagingTargetMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetGlobalENBID")
	}
	return value, aper.OperationError(nil, "MMEPagingTargetGlobalENBID")
}

// NewMMEPagingTargetTAI constructs a checked complete value.
func NewMMEPagingTargetTAI(v s31.TAI, options ...aper.BuildOption) (s31.MMEPagingTarget, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	value := BridgeNewMMEPagingTargetTAILegacy(v)
	if _, err := s31.BridgeMMEPagingTargetMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s31.MMEPagingTarget{}, aper.OperationError(err, "MMEPagingTargetTAI")
	}
	return value, aper.OperationError(nil, "MMEPagingTargetTAI")
}

// NewWarningAreaListCellIDList constructs a checked complete value.
func NewWarningAreaListCellIDList(v s17.ECGIList, options ...aper.BuildOption) (s32.WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	value := BridgeNewWarningAreaListCellIDListLegacy(v)
	if _, err := s32.BridgeWarningAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListCellIDList")
	}
	return value, aper.OperationError(nil, "WarningAreaListCellIDList")
}

// NewWarningAreaListTrackingAreaListforWarning constructs a checked complete value.
func NewWarningAreaListTrackingAreaListforWarning(v s32.TAIListforWarning, options ...aper.BuildOption) (s32.WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	value := BridgeNewWarningAreaListTrackingAreaListforWarningLegacy(v)
	if _, err := s32.BridgeWarningAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListTrackingAreaListforWarning")
	}
	return value, aper.OperationError(nil, "WarningAreaListTrackingAreaListforWarning")
}

// NewWarningAreaListEmergencyAreaIDList constructs a checked complete value.
func NewWarningAreaListEmergencyAreaIDList(v s00.EmergencyAreaIDList, options ...aper.BuildOption) (s32.WarningAreaList, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	value := BridgeNewWarningAreaListEmergencyAreaIDListLegacy(v)
	if _, err := s32.BridgeWarningAreaListMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s32.WarningAreaList{}, aper.OperationError(err, "WarningAreaListEmergencyAreaIDList")
	}
	return value, aper.OperationError(nil, "WarningAreaListEmergencyAreaIDList")
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
	TAI               s31.TAI                       `asn1:"tag:0,context,implicit"`
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

// LocationReport represents the ASN.1 type LocationReport (SEQUENCE).
type LocationReport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s31.LocationReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                          `asn1:"-" json:"-"`
	extCount         int64                         `asn1:"-" json:"-"`
	extPresent       []bool                        `asn1:"-" json:"-"`
	extData          [][]byte                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding        `asn1:"-" json:"-"`
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

// KillRequest represents the ASN.1 type KillRequest (SEQUENCE).
type KillRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s32.KillRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                       `asn1:"-" json:"-"`
	extCount         int64                      `asn1:"-" json:"-"`
	extPresent       []bool                     `asn1:"-" json:"-"`
	extData          [][]byte                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// KillResponse represents the ASN.1 type KillResponse (SEQUENCE).
type KillResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s32.KillResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                        `asn1:"-" json:"-"`
	extCount         int64                       `asn1:"-" json:"-"`
	extPresent       []bool                      `asn1:"-" json:"-"`
	extData          [][]byte                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding      `asn1:"-" json:"-"`
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
	if err := s31.BridgeTAIMethodMarshalAPERTo(&v.TAI, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	if err := s31.BridgeTAIMethodUnmarshalAPERFrom(&v.TAI, bb); err != nil {
		return runtime.WrapDecodePath(err, "TAI")
	}
	bb.LeaveComponent(toleranceMark_tai)
	if opt_ieextensions {
		tmp_ieextensions := make(s11.TAIItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s11.TAIItemExtIEsExtField
				if err := s11.BridgeTAIItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes LocationReport to APER format.
func (v *LocationReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *LocationReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s31.BridgeLocationReportIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes LocationReport from APER format.
func (v *LocationReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LocationReport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LocationReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LocationReport")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LocationReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "LocationReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "LocationReport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *LocationReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LocationReport{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s31.LocationReportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s31.LocationReportIEField
			if err := s31.BridgeLocationReportIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes KillRequest to APER format.
func (v *KillRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *KillRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s32.BridgeKillRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes KillRequest from APER format.
func (v *KillRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes KillRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *KillRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "KillRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "KillRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "KillRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *KillRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s32.KillRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s32.KillRequestIEField
			if err := s32.BridgeKillRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes KillResponse to APER format.
func (v *KillResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *KillResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s32.BridgeKillResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes KillResponse from APER format.
func (v *KillResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes KillResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *KillResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "KillResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "KillResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "KillResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "KillResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *KillResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = KillResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(s32.KillResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s32.KillResponseIEField
			if err := s32.BridgeKillResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *KillRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "KillRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "KillRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v KillRequest) WithoutReplay() KillRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero KillRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *KillResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "KillResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "KillResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v KillResponse) WithoutReplay() KillResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero KillResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LocationReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "LocationReport", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "LocationReport", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LocationReport) WithoutReplay() LocationReport {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero LocationReport
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
func (v *KillRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *KillRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("KillRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("KillRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *KillRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("KillRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("KillRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *KillResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *KillResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("KillResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("KillResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *KillResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("KillResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("KillResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *LocationReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *LocationReport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *LocationReport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("LocationReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("LocationReport.Extensions[%d]", index))
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
func (v *KillRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "KillRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *KillRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "KillRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APKillRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "KillRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "KillRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *KillRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "KillRequest")
}
func (v *KillRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "KillRequest")
}
func (v *KillRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APKillRequest(v, &s)
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
func (v *KillRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *KillRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *KillResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "KillResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *KillResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "KillResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APKillResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "KillResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "KillResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *KillResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "KillResponse")
}
func (v *KillResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "KillResponse")
}
func (v *KillResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APKillResponse(v, &s)
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
func (v *KillResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *KillResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *LocationReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "LocationReport")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *LocationReport) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LocationReport")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APLocationReport(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "LocationReport")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "LocationReport")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *LocationReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "LocationReport")
}
func (v *LocationReport) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "LocationReport")
}
func (v *LocationReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APLocationReport(v, &s)
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
func (v *LocationReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *LocationReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *KillRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "KillRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded KillRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APKillRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = KillRequest{}
		return report, aper.OperationError(err, "KillRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "KillRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *KillResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "KillResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded KillResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APKillResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = KillResponse{}
		return report, aper.OperationError(err, "KillResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "KillResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *LocationReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LocationReport")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded LocationReport
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APLocationReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = LocationReport{}
		return report, aper.OperationError(err, "LocationReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LocationReport")
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

type WriteReplaceWarningRequestIEValue struct {
	id                                   s00.ProtocolIEID
	received                             aper.WireSpan
	replay                               aper.Snapshot
	opaque                               aper.OpaqueOpenType
	isOpaque                             bool
	rowMessageIdentifier                 *s00.MessageIdentifier
	rowSerialNumber                      *s00.SerialNumber
	rowWarningAreaList                   *s32.WarningAreaList
	rowRepetitionPeriod                  *s00.RepetitionPeriod
	rowExtendedRepetitionPeriod          *s00.ExtendedRepetitionPeriod
	rowNumberofBroadcastRequest          *s00.NumberofBroadcastRequest
	rowWarningType                       *s00.WarningType
	rowWarningSecurityInfo               *s00.WarningSecurityInfo
	rowDataCodingScheme                  *s00.DataCodingScheme
	rowWarningMessageContents            *s00.WarningMessageContents
	rowConcurrentWarningMessageIndicator *s00.ConcurrentWarningMessageIndicator
	rowWarningAreaCoordinates            *s00.WarningAreaCoordinates
}

func (v WriteReplaceWarningRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(111):
		return v.rowMessageIdentifier != nil
	case s00.ProtocolIEID(112):
		return v.rowSerialNumber != nil
	case s00.ProtocolIEID(113):
		return v.rowWarningAreaList != nil
	case s00.ProtocolIEID(114):
		return v.rowRepetitionPeriod != nil
	case s00.ProtocolIEID(144):
		return v.rowExtendedRepetitionPeriod != nil
	case s00.ProtocolIEID(115):
		return v.rowNumberofBroadcastRequest != nil
	case s00.ProtocolIEID(116):
		return v.rowWarningType != nil
	case s00.ProtocolIEID(117):
		return v.rowWarningSecurityInfo != nil
	case s00.ProtocolIEID(118):
		return v.rowDataCodingScheme != nil
	case s00.ProtocolIEID(119):
		return v.rowWarningMessageContents != nil
	case s00.ProtocolIEID(142):
		return v.rowConcurrentWarningMessageIndicator != nil
	case s00.ProtocolIEID(286):
		return v.rowWarningAreaCoordinates != nil
	}
	return false
}

// Opaque returns the retained opaque open value of WriteReplaceWarningRequestIEValue and reports whether the opaque alternative is selected.
func (v *WriteReplaceWarningRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (WriteReplaceWarningRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs"}}
}
func (WriteReplaceWarningRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(111):
		return aper.UnknownSelector
	case s00.ProtocolIEID(112):
		return aper.UnknownSelector
	case s00.ProtocolIEID(113):
		return aper.UnknownSelector
	case s00.ProtocolIEID(114):
		return aper.UnknownSelector
	case s00.ProtocolIEID(144):
		return aper.UnknownSelector
	case s00.ProtocolIEID(115):
		return aper.UnknownSelector
	case s00.ProtocolIEID(116):
		return aper.UnknownSelector
	case s00.ProtocolIEID(117):
		return aper.UnknownSelector
	case s00.ProtocolIEID(118):
		return aper.UnknownSelector
	case s00.ProtocolIEID(119):
		return aper.UnknownSelector
	case s00.ProtocolIEID(142):
		return aper.UnknownSelector
	case s00.ProtocolIEID(286):
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
	case s00.ProtocolIEID(143):
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

// AsMessageIdentifier returns the selected MessageIdentifier value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsMessageIdentifier() (*s00.MessageIdentifier, bool) {
	if v == nil || v.id != s00.ProtocolIEID(111) || v.rowMessageIdentifier == nil {
		return nil, false
	}
	return v.rowMessageIdentifier, true
}

// AsSerialNumber returns the selected SerialNumber value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsSerialNumber() (*s00.SerialNumber, bool) {
	if v == nil || v.id != s00.ProtocolIEID(112) || v.rowSerialNumber == nil {
		return nil, false
	}
	return v.rowSerialNumber, true
}

// AsWarningAreaList returns the selected WarningAreaList value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsWarningAreaList() (*s32.WarningAreaList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(113) || v.rowWarningAreaList == nil {
		return nil, false
	}
	return v.rowWarningAreaList, true
}

// AsRepetitionPeriod returns the selected RepetitionPeriod value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsRepetitionPeriod() (*s00.RepetitionPeriod, bool) {
	if v == nil || v.id != s00.ProtocolIEID(114) || v.rowRepetitionPeriod == nil {
		return nil, false
	}
	return v.rowRepetitionPeriod, true
}

// AsExtendedRepetitionPeriod returns the selected ExtendedRepetitionPeriod value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsExtendedRepetitionPeriod() (*s00.ExtendedRepetitionPeriod, bool) {
	if v == nil || v.id != s00.ProtocolIEID(144) || v.rowExtendedRepetitionPeriod == nil {
		return nil, false
	}
	return v.rowExtendedRepetitionPeriod, true
}

// AsNumberofBroadcastRequest returns the selected NumberofBroadcastRequest value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsNumberofBroadcastRequest() (*s00.NumberofBroadcastRequest, bool) {
	if v == nil || v.id != s00.ProtocolIEID(115) || v.rowNumberofBroadcastRequest == nil {
		return nil, false
	}
	return v.rowNumberofBroadcastRequest, true
}

// AsWarningType returns the selected WarningType value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsWarningType() (*s00.WarningType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(116) || v.rowWarningType == nil {
		return nil, false
	}
	return v.rowWarningType, true
}

// AsWarningSecurityInfo returns the selected WarningSecurityInfo value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsWarningSecurityInfo() (*s00.WarningSecurityInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(117) || v.rowWarningSecurityInfo == nil {
		return nil, false
	}
	return v.rowWarningSecurityInfo, true
}

// AsDataCodingScheme returns the selected DataCodingScheme value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsDataCodingScheme() (*s00.DataCodingScheme, bool) {
	if v == nil || v.id != s00.ProtocolIEID(118) || v.rowDataCodingScheme == nil {
		return nil, false
	}
	return v.rowDataCodingScheme, true
}

// AsWarningMessageContents returns the selected WarningMessageContents value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsWarningMessageContents() (*s00.WarningMessageContents, bool) {
	if v == nil || v.id != s00.ProtocolIEID(119) || v.rowWarningMessageContents == nil {
		return nil, false
	}
	return v.rowWarningMessageContents, true
}

// AsConcurrentWarningMessageIndicator returns the selected ConcurrentWarningMessageIndicator value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsConcurrentWarningMessageIndicator() (*s00.ConcurrentWarningMessageIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(142) || v.rowConcurrentWarningMessageIndicator == nil {
		return nil, false
	}
	return v.rowConcurrentWarningMessageIndicator, true
}

// AsWarningAreaCoordinates returns the selected WarningAreaCoordinates value of WriteReplaceWarningRequestIEValue and reports whether that alternative is active.
func (v *WriteReplaceWarningRequestIEValue) AsWarningAreaCoordinates() (*s00.WarningAreaCoordinates, bool) {
	if v == nil || v.id != s00.ProtocolIEID(286) || v.rowWarningAreaCoordinates == nil {
		return nil, false
	}
	return v.rowWarningAreaCoordinates, true
}
func (v WriteReplaceWarningRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WriteReplaceWarningRequestIEValue, error) {
	out := WriteReplaceWarningRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(111):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MessageIdentifier, error) {
			var v struct{ Value s00.MessageIdentifier }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowMessageIdentifier = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(112):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SerialNumber, error) {
			var v struct{ Value s00.SerialNumber }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
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
		out.rowSerialNumber = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(113):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s32.WarningAreaList
		child := scope
		if err := s32.BridgeWarningAreaListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "WarningAreaList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WarningAreaList")
		if err != nil {
			return out, err
		}
		*s32.BridgeWarningAreaListFieldPerPadding(&value) = padding.Padding()
		*s32.BridgeWarningAreaListFieldReceived(&value) = true
		raw.RetainContents(s32.BridgeWarningAreaListFieldReceivedBytes(&value))
		*s32.BridgeWarningAreaListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowWarningAreaList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(114):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false)
		value := s00.RepetitionPeriod(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "RepetitionPeriod:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowRepetitionPeriod = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(144):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(4096), s07.BridgeInt64Ptr(131071), false)
		value := s00.ExtendedRepetitionPeriod(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ExtendedRepetitionPeriod:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowExtendedRepetitionPeriod = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(115):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
		value := s00.NumberofBroadcastRequest(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NumberofBroadcastRequest:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNumberofBroadcastRequest = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(116):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.WarningType, error) {
			var v struct{ Value s00.WarningType }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.WarningType(val_value)
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
		out.rowWarningType = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(117):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.WarningSecurityInfo, error) {
			var v struct{ Value s00.WarningSecurityInfo }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 50, 50, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.WarningSecurityInfo(val_value)
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
		out.rowWarningSecurityInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(118):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.DataCodingScheme, error) {
			var v struct{ Value s00.DataCodingScheme }
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
		out.rowDataCodingScheme = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(119):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.WarningMessageContents, error) {
			var v struct{ Value s00.WarningMessageContents }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 1, 9600, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.WarningMessageContents(val_value)
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
		out.rowWarningMessageContents = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(142):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, false, aper.EnumerationSource{KnownExtensions: 0, Path: "ConcurrentWarningMessageIndicator"})
		value := s00.ConcurrentWarningMessageIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ConcurrentWarningMessageIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowConcurrentWarningMessageIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(286):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.WarningAreaCoordinates, error) {
			var v struct{ Value s00.WarningAreaCoordinates }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 1, 1024, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.WarningAreaCoordinates(val_value)
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
		out.rowWarningAreaCoordinates = &value
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
func (v WriteReplaceWarningRequestIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v WriteReplaceWarningRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(111):
		if v.rowMessageIdentifier == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-MessageIdentifier:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MessageIdentifier, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MessageIdentifier }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMessageIdentifier, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(112):
		if v.rowSerialNumber == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-SerialNumber:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SerialNumber, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SerialNumber }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSerialNumber, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(113):
		if v.rowWarningAreaList == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-WarningAreaList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s32.BridgeWarningAreaListMethodMarshalAPERBudget(v.rowWarningAreaList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(114):
		if v.rowRepetitionPeriod == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-RepetitionPeriod:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowRepetitionPeriod), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4095), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(144):
		if v.rowExtendedRepetitionPeriod == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-ExtendedRepetitionPeriod:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowExtendedRepetitionPeriod), s07.BridgeInt64Ptr(4096), s07.BridgeInt64Ptr(131071), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(115):
		if v.rowNumberofBroadcastRequest == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-NumberofBroadcastRequest:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowNumberofBroadcastRequest), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(116):
		if v.rowWarningType == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-WarningType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.WarningType, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.WarningType }{Value: value}
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
		})(*v.rowWarningType, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(117):
		if v.rowWarningSecurityInfo == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-WarningSecurityInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.WarningSecurityInfo, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.WarningSecurityInfo }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 50, 50, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowWarningSecurityInfo, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(118):
		if v.rowDataCodingScheme == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-DataCodingScheme:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.DataCodingScheme, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.DataCodingScheme }{Value: value}
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
		})(*v.rowDataCodingScheme, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(119):
		if v.rowWarningMessageContents == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-WarningMessageContents:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.WarningMessageContents, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.WarningMessageContents }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 9600, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowWarningMessageContents, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(142):
		if v.rowConcurrentWarningMessageIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-ConcurrentWarningMessageIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowConcurrentWarningMessageIndicator), 1, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(286):
		if v.rowWarningAreaCoordinates == nil {
			return nil, fmt.Errorf("%s missing value", "WriteReplaceWarningRequestIEs.id-WarningAreaCoordinates:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.WarningAreaCoordinates, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.WarningAreaCoordinates }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 1024, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowWarningAreaCoordinates, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WriteReplaceWarningRequestIEValue:", v.id)
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
			var zero ENBDirectInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(121), raw)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, err
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
			var zero MMEDirectInformationTransferIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(122), raw)
			if err != nil {
				var empty InterSystemInformationTransferType
				return empty, err
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
			var zero TAIItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(47), raw)
			if err != nil {
				var empty TAIItem
				return empty, err
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

type WriteReplaceWarningRequestIETable struct{}

func WriteReplaceWarningRequestIEs() WriteReplaceWarningRequestIETable {
	return WriteReplaceWarningRequestIETable{}
}

// ID returns the ASN.1 object-set identity of WriteReplaceWarningRequestIETable.
func (WriteReplaceWarningRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by WriteReplaceWarningRequestIETable.
func (WriteReplaceWarningRequestIETable) Table() s00.WriteReplaceWarningRequestIEValueIETable {
	return func() s00.WriteReplaceWarningRequestIEValueIETable {
		sealed := s00.WriteReplaceWarningRequestIEValueIETable{}
		*s00.BridgeWriteReplaceWarningRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (WriteReplaceWarningRequestIETable) infoMessageIdentifier() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(111), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MessageIdentifier"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-MessageIdentifier"}}}
}

// MessageIdentifier returns the typed binding for the MessageIdentifier row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) MessageIdentifier() WriteReplaceWarningRequestMessageIdentifierIEBinding {
	return WriteReplaceWarningRequestMessageIdentifierIEBinding{info: t.infoMessageIdentifier(), codec: func() s01.MessageIdentifierValueCodec {
		sealed := s01.MessageIdentifierValueCodec{}
		*s01.BridgeMessageIdentifierValueCodecFieldPath(&sealed) = "MessageIdentifier"
		*s01.BridgeMessageIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MessageIdentifier, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(111), raw)
			if err != nil {
				var empty s00.MessageIdentifier
				return empty, err
			}
			value, ok := decoded.AsMessageIdentifier()
			if !ok {
				var empty s00.MessageIdentifier
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-MessageIdentifier: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMessageIdentifierValueCodecFieldEncode(&sealed) = func(value s00.MessageIdentifier, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMessageIdentifierValueCodecFieldCapture(&sealed) = func(v s00.MessageIdentifier, options aper.DecodeState) (s00.MessageIdentifier, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMessageIdentifier(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeMessageIdentifierValueCodecFieldCompare(&sealed) = func(v s00.MessageIdentifier, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMessageIdentifier(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeMessageIdentifierValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MessageIdentifier"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MessageIdentifier) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(111), rowMessageIdentifier: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.MessageIdentifier, bool) {
			return value.AsMessageIdentifier()
		}}
}
func (WriteReplaceWarningRequestIETable) infoSerialNumber() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(112), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SerialNumber"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-SerialNumber"}}}
}

// SerialNumber returns the typed binding for the SerialNumber row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) SerialNumber() WriteReplaceWarningRequestSerialNumberIEBinding {
	return WriteReplaceWarningRequestSerialNumberIEBinding{info: t.infoSerialNumber(), codec: func() s01.SerialNumberValueCodec {
		sealed := s01.SerialNumberValueCodec{}
		*s01.BridgeSerialNumberValueCodecFieldPath(&sealed) = "SerialNumber"
		*s01.BridgeSerialNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SerialNumber, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(112), raw)
			if err != nil {
				var empty s00.SerialNumber
				return empty, err
			}
			value, ok := decoded.AsSerialNumber()
			if !ok {
				var empty s00.SerialNumber
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-SerialNumber: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSerialNumberValueCodecFieldEncode(&sealed) = func(value s00.SerialNumber, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSerialNumberValueCodecFieldCapture(&sealed) = func(v s00.SerialNumber, options aper.DecodeState) (s00.SerialNumber, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSerialNumber(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSerialNumberValueCodecFieldCompare(&sealed) = func(v s00.SerialNumber, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APSerialNumber(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeSerialNumberValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SerialNumber"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SerialNumber) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(112), rowSerialNumber: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.SerialNumber, bool) {
			return value.AsSerialNumber()
		}}
}
func (WriteReplaceWarningRequestIETable) infoWarningAreaList() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(113), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningAreaList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-WarningAreaList"}}}
}

// WarningAreaList returns the typed binding for the WarningAreaList row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) WarningAreaList() WriteReplaceWarningRequestWarningAreaListIEBinding {
	return WriteReplaceWarningRequestWarningAreaListIEBinding{info: t.infoWarningAreaList(), codec: func() s32.WarningAreaListValueCodec {
		sealed := s32.WarningAreaListValueCodec{}
		*s32.BridgeWarningAreaListValueCodecFieldPath(&sealed) = "WarningAreaList"
		*s32.BridgeWarningAreaListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WarningAreaList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s32.WarningAreaList
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(113), raw)
			if err != nil {
				var empty s32.WarningAreaList
				return empty, err
			}
			value, ok := decoded.AsWarningAreaList()
			if !ok {
				var empty s32.WarningAreaList
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningAreaList: no selected value")
			}
			return *value, nil
		}
		*s32.BridgeWarningAreaListValueCodecFieldEncode(&sealed) = func(value s32.WarningAreaList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}).encodeFresh(fresh, budget)
		}
		*s32.BridgeWarningAreaListValueCodecFieldCapture(&sealed) = func(v s32.WarningAreaList, options aper.DecodeState) (s32.WarningAreaList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s32.BridgeCaptureS1APWarningAreaList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeWarningAreaListValueCodecFieldCompare(&sealed) = func(v s32.WarningAreaList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s32.BridgeCompareS1APWarningAreaList(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s32.BridgeWarningAreaListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningAreaList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s32.WarningAreaList) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(113), rowWarningAreaList: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s32.WarningAreaList, bool) {
			return value.AsWarningAreaList()
		}}
}
func (WriteReplaceWarningRequestIETable) infoRepetitionPeriod() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(114), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RepetitionPeriod"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-RepetitionPeriod"}}}
}

// RepetitionPeriod returns the typed binding for the RepetitionPeriod row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) RepetitionPeriod() WriteReplaceWarningRequestRepetitionPeriodIEBinding {
	return WriteReplaceWarningRequestRepetitionPeriodIEBinding{info: t.infoRepetitionPeriod(), codec: func() s01.RepetitionPeriodValueCodec {
		sealed := s01.RepetitionPeriodValueCodec{}
		*s01.BridgeRepetitionPeriodValueCodecFieldPath(&sealed) = "RepetitionPeriod"
		*s01.BridgeRepetitionPeriodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.RepetitionPeriod, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.RepetitionPeriod
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(114), raw)
			if err != nil {
				var empty s00.RepetitionPeriod
				return empty, err
			}
			value, ok := decoded.AsRepetitionPeriod()
			if !ok {
				var empty s00.RepetitionPeriod
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-RepetitionPeriod: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeRepetitionPeriodValueCodecFieldEncode(&sealed) = func(value s00.RepetitionPeriod, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(114), rowRepetitionPeriod: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeRepetitionPeriodValueCodecFieldCapture(&sealed) = func(v s00.RepetitionPeriod, options aper.DecodeState) (s00.RepetitionPeriod, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APRepetitionPeriod(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeRepetitionPeriodValueCodecFieldCompare(&sealed) = func(v s00.RepetitionPeriod, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APRepetitionPeriod(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeRepetitionPeriodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RepetitionPeriod"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.RepetitionPeriod) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(114), rowRepetitionPeriod: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.RepetitionPeriod, bool) {
			return value.AsRepetitionPeriod()
		}}
}
func (WriteReplaceWarningRequestIETable) infoExtendedRepetitionPeriod() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(144), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExtendedRepetitionPeriod"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-ExtendedRepetitionPeriod"}}}
}

// ExtendedRepetitionPeriod returns the typed binding for the ExtendedRepetitionPeriod row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) ExtendedRepetitionPeriod() WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding {
	return WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding{info: t.infoExtendedRepetitionPeriod(), codec: func() s00.ExtendedRepetitionPeriodValueCodec {
		sealed := s00.ExtendedRepetitionPeriodValueCodec{}
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldPath(&sealed) = "ExtendedRepetitionPeriod"
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedRepetitionPeriod, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedRepetitionPeriod
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(144), raw)
			if err != nil {
				var empty s00.ExtendedRepetitionPeriod
				return empty, err
			}
			value, ok := decoded.AsExtendedRepetitionPeriod()
			if !ok {
				var empty s00.ExtendedRepetitionPeriod
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-ExtendedRepetitionPeriod: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldEncode(&sealed) = func(value s00.ExtendedRepetitionPeriod, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(144), rowExtendedRepetitionPeriod: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldCapture(&sealed) = func(v s00.ExtendedRepetitionPeriod, options aper.DecodeState) (s00.ExtendedRepetitionPeriod, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedRepetitionPeriod(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldCompare(&sealed) = func(v s00.ExtendedRepetitionPeriod, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APExtendedRepetitionPeriod(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeExtendedRepetitionPeriodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedRepetitionPeriod"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedRepetitionPeriod) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(144), rowExtendedRepetitionPeriod: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.ExtendedRepetitionPeriod, bool) {
			return value.AsExtendedRepetitionPeriod()
		}}
}
func (WriteReplaceWarningRequestIETable) infoNumberofBroadcastRequest() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(115), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NumberofBroadcastRequest"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-NumberofBroadcastRequest"}}}
}

// NumberofBroadcastRequest returns the typed binding for the NumberofBroadcastRequest row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) NumberofBroadcastRequest() WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding {
	return WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding{info: t.infoNumberofBroadcastRequest(), codec: func() s01.NumberofBroadcastRequestValueCodec {
		sealed := s01.NumberofBroadcastRequestValueCodec{}
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldPath(&sealed) = "NumberofBroadcastRequest"
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberofBroadcastRequest, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NumberofBroadcastRequest
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(115), raw)
			if err != nil {
				var empty s00.NumberofBroadcastRequest
				return empty, err
			}
			value, ok := decoded.AsNumberofBroadcastRequest()
			if !ok {
				var empty s00.NumberofBroadcastRequest
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-NumberofBroadcastRequest: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldEncode(&sealed) = func(value s00.NumberofBroadcastRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(115), rowNumberofBroadcastRequest: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldCapture(&sealed) = func(v s00.NumberofBroadcastRequest, options aper.DecodeState) (s00.NumberofBroadcastRequest, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNumberofBroadcastRequest(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldCompare(&sealed) = func(v s00.NumberofBroadcastRequest, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNumberofBroadcastRequest(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNumberofBroadcastRequestValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberofBroadcastRequest"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NumberofBroadcastRequest) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(115), rowNumberofBroadcastRequest: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.NumberofBroadcastRequest, bool) {
			return value.AsNumberofBroadcastRequest()
		}}
}
func (WriteReplaceWarningRequestIETable) infoWarningType() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(116), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-WarningType"}}}
}

// WarningType returns the typed binding for the WarningType row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) WarningType() WriteReplaceWarningRequestWarningTypeIEBinding {
	return WriteReplaceWarningRequestWarningTypeIEBinding{info: t.infoWarningType(), codec: func() s02.WarningTypeValueCodec {
		sealed := s02.WarningTypeValueCodec{}
		*s02.BridgeWarningTypeValueCodecFieldPath(&sealed) = "WarningType"
		*s02.BridgeWarningTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WarningType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.WarningType
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(116), raw)
			if err != nil {
				var empty s00.WarningType
				return empty, err
			}
			value, ok := decoded.AsWarningType()
			if !ok {
				var empty s00.WarningType
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningType: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeWarningTypeValueCodecFieldEncode(&sealed) = func(value s00.WarningType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(116), rowWarningType: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeWarningTypeValueCodecFieldCapture(&sealed) = func(v s00.WarningType, options aper.DecodeState) (s00.WarningType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWarningType(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWarningTypeValueCodecFieldCompare(&sealed) = func(v s00.WarningType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APWarningType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s02.BridgeWarningTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.WarningType) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(116), rowWarningType: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.WarningType, bool) { return value.AsWarningType() }}
}
func (WriteReplaceWarningRequestIETable) infoWarningSecurityInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(117), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningSecurityInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-WarningSecurityInfo"}}}
}

// WarningSecurityInfo returns the typed binding for the WarningSecurityInfo row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) WarningSecurityInfo() WriteReplaceWarningRequestWarningSecurityInfoIEBinding {
	return WriteReplaceWarningRequestWarningSecurityInfoIEBinding{info: t.infoWarningSecurityInfo(), codec: func() s02.WarningSecurityInfoValueCodec {
		sealed := s02.WarningSecurityInfoValueCodec{}
		*s02.BridgeWarningSecurityInfoValueCodecFieldPath(&sealed) = "WarningSecurityInfo"
		*s02.BridgeWarningSecurityInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WarningSecurityInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.WarningSecurityInfo
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(117), raw)
			if err != nil {
				var empty s00.WarningSecurityInfo
				return empty, err
			}
			value, ok := decoded.AsWarningSecurityInfo()
			if !ok {
				var empty s00.WarningSecurityInfo
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningSecurityInfo: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeWarningSecurityInfoValueCodecFieldEncode(&sealed) = func(value s00.WarningSecurityInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(117), rowWarningSecurityInfo: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeWarningSecurityInfoValueCodecFieldCapture(&sealed) = func(v s00.WarningSecurityInfo, options aper.DecodeState) (s00.WarningSecurityInfo, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWarningSecurityInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWarningSecurityInfoValueCodecFieldCompare(&sealed) = func(v s00.WarningSecurityInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APWarningSecurityInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWarningSecurityInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningSecurityInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.WarningSecurityInfo) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(117), rowWarningSecurityInfo: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.WarningSecurityInfo, bool) {
			return value.AsWarningSecurityInfo()
		}}
}
func (WriteReplaceWarningRequestIETable) infoDataCodingScheme() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(118), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DataCodingScheme"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-DataCodingScheme"}}}
}

// DataCodingScheme returns the typed binding for the DataCodingScheme row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) DataCodingScheme() WriteReplaceWarningRequestDataCodingSchemeIEBinding {
	return WriteReplaceWarningRequestDataCodingSchemeIEBinding{info: t.infoDataCodingScheme(), codec: func() s00.DataCodingSchemeValueCodec {
		sealed := s00.DataCodingSchemeValueCodec{}
		*s00.BridgeDataCodingSchemeValueCodecFieldPath(&sealed) = "DataCodingScheme"
		*s00.BridgeDataCodingSchemeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DataCodingScheme, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DataCodingScheme
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(118), raw)
			if err != nil {
				var empty s00.DataCodingScheme
				return empty, err
			}
			value, ok := decoded.AsDataCodingScheme()
			if !ok {
				var empty s00.DataCodingScheme
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-DataCodingScheme: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDataCodingSchemeValueCodecFieldEncode(&sealed) = func(value s00.DataCodingScheme, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(118), rowDataCodingScheme: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDataCodingSchemeValueCodecFieldCapture(&sealed) = func(v s00.DataCodingScheme, options aper.DecodeState) (s00.DataCodingScheme, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APDataCodingScheme(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDataCodingSchemeValueCodecFieldCompare(&sealed) = func(v s00.DataCodingScheme, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDataCodingScheme(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeDataCodingSchemeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DataCodingScheme"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DataCodingScheme) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(118), rowDataCodingScheme: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.DataCodingScheme, bool) {
			return value.AsDataCodingScheme()
		}}
}
func (WriteReplaceWarningRequestIETable) infoWarningMessageContents() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(119), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningMessageContents"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-WarningMessageContents"}}}
}

// WarningMessageContents returns the typed binding for the WarningMessageContents row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) WarningMessageContents() WriteReplaceWarningRequestWarningMessageContentsIEBinding {
	return WriteReplaceWarningRequestWarningMessageContentsIEBinding{info: t.infoWarningMessageContents(), codec: func() s02.WarningMessageContentsValueCodec {
		sealed := s02.WarningMessageContentsValueCodec{}
		*s02.BridgeWarningMessageContentsValueCodecFieldPath(&sealed) = "WarningMessageContents"
		*s02.BridgeWarningMessageContentsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WarningMessageContents, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.WarningMessageContents
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(119), raw)
			if err != nil {
				var empty s00.WarningMessageContents
				return empty, err
			}
			value, ok := decoded.AsWarningMessageContents()
			if !ok {
				var empty s00.WarningMessageContents
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningMessageContents: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeWarningMessageContentsValueCodecFieldEncode(&sealed) = func(value s00.WarningMessageContents, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(119), rowWarningMessageContents: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeWarningMessageContentsValueCodecFieldCapture(&sealed) = func(v s00.WarningMessageContents, options aper.DecodeState) (s00.WarningMessageContents, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWarningMessageContents(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWarningMessageContentsValueCodecFieldCompare(&sealed) = func(v s00.WarningMessageContents, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APWarningMessageContents(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWarningMessageContentsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningMessageContents"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.WarningMessageContents) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(119), rowWarningMessageContents: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.WarningMessageContents, bool) {
			return value.AsWarningMessageContents()
		}}
}
func (WriteReplaceWarningRequestIETable) infoConcurrentWarningMessageIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(142), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ConcurrentWarningMessageIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-ConcurrentWarningMessageIndicator"}}}
}

// ConcurrentWarningMessageIndicator returns the typed binding for the ConcurrentWarningMessageIndicator row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) ConcurrentWarningMessageIndicator() WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding {
	return WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding{info: t.infoConcurrentWarningMessageIndicator(), codec: func() s00.ConcurrentWarningMessageIndicatorValueCodec {
		sealed := s00.ConcurrentWarningMessageIndicatorValueCodec{}
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldPath(&sealed) = "ConcurrentWarningMessageIndicator"
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ConcurrentWarningMessageIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ConcurrentWarningMessageIndicator
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(142), raw)
			if err != nil {
				var empty s00.ConcurrentWarningMessageIndicator
				return empty, err
			}
			value, ok := decoded.AsConcurrentWarningMessageIndicator()
			if !ok {
				var empty s00.ConcurrentWarningMessageIndicator
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-ConcurrentWarningMessageIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldEncode(&sealed) = func(value s00.ConcurrentWarningMessageIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(142), rowConcurrentWarningMessageIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldCapture(&sealed) = func(v s00.ConcurrentWarningMessageIndicator, options aper.DecodeState) (s00.ConcurrentWarningMessageIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APConcurrentWarningMessageIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldCompare(&sealed) = func(v s00.ConcurrentWarningMessageIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APConcurrentWarningMessageIndicator(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeConcurrentWarningMessageIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ConcurrentWarningMessageIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ConcurrentWarningMessageIndicator) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(142), rowConcurrentWarningMessageIndicator: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.ConcurrentWarningMessageIndicator, bool) {
			return value.AsConcurrentWarningMessageIndicator()
		}}
}
func (WriteReplaceWarningRequestIETable) infoWarningAreaCoordinates() s00.FieldInfo {
	return s00.FieldInfo{Table: WriteReplaceWarningRequestIEs().ID(), ID: s00.ProtocolIEID(286), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WarningAreaCoordinates"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "WriteReplaceWarningRequestIEs", Row: "id-WarningAreaCoordinates"}}}
}

// WarningAreaCoordinates returns the typed binding for the WarningAreaCoordinates row of WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) WarningAreaCoordinates() WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding {
	return WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding{info: t.infoWarningAreaCoordinates(), codec: func() s02.WarningAreaCoordinatesValueCodec {
		sealed := s02.WarningAreaCoordinatesValueCodec{}
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldPath(&sealed) = "WarningAreaCoordinates"
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WarningAreaCoordinates, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.WarningAreaCoordinates
				return empty, err
			}
			var zero WriteReplaceWarningRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(286), raw)
			if err != nil {
				var empty s00.WarningAreaCoordinates
				return empty, err
			}
			value, ok := decoded.AsWarningAreaCoordinates()
			if !ok {
				var empty s00.WarningAreaCoordinates
				return empty, fmt.Errorf("binding WriteReplaceWarningRequestIEs.id-WarningAreaCoordinates: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldEncode(&sealed) = func(value s00.WarningAreaCoordinates, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(286), rowWarningAreaCoordinates: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldCapture(&sealed) = func(v s00.WarningAreaCoordinates, options aper.DecodeState) (s00.WarningAreaCoordinates, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APWarningAreaCoordinates(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldCompare(&sealed) = func(v s00.WarningAreaCoordinates, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APWarningAreaCoordinates(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeWarningAreaCoordinatesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WarningAreaCoordinates"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.WarningAreaCoordinates) WriteReplaceWarningRequestIEValue {
			return WriteReplaceWarningRequestIEValue{id: s00.ProtocolIEID(286), rowWarningAreaCoordinates: &value}
		}, get: func(value *WriteReplaceWarningRequestIEValue) (*s00.WarningAreaCoordinates, bool) {
			return value.AsWarningAreaCoordinates()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in WriteReplaceWarningRequestIETable.
func (t WriteReplaceWarningRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WriteReplaceWarningRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(111):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MessageIdentifier requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(112):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SerialNumber requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(113):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningAreaList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(114):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RepetitionPeriod requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(144):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ExtendedRepetitionPeriod requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(115):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NumberofBroadcastRequest requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(116):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(117):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningSecurityInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(118):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-DataCodingScheme requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(119):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningMessageContents requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(142):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ConcurrentWarningMessageIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(286):
		return WriteReplaceWarningRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WarningAreaCoordinates requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WriteReplaceWarningRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return WriteReplaceWarningRequestIEField{Id: id, Criticality: criticality, Value: WriteReplaceWarningRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ConcurrentWarningMessageIndicatorCodec binds the complete APER value type.
func ConcurrentWarningMessageIndicatorCodec() s00.ConcurrentWarningMessageIndicatorValueCodec {
	return WriteReplaceWarningRequestIEs().ConcurrentWarningMessageIndicator().Codec()
}

// DataCodingSchemeCodec binds the complete APER value type.
func DataCodingSchemeCodec() s00.DataCodingSchemeValueCodec {
	return WriteReplaceWarningRequestIEs().DataCodingScheme().Codec()
}

// ExtendedRepetitionPeriodCodec binds the complete APER value type.
func ExtendedRepetitionPeriodCodec() s00.ExtendedRepetitionPeriodValueCodec {
	return WriteReplaceWarningRequestIEs().ExtendedRepetitionPeriod().Codec()
}

// InterSystemInformationTransferTypeCodec binds the complete APER value type.
func InterSystemInformationTransferTypeCodec() InterSystemInformationTransferTypeValueCodec {
	return ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Codec()
}

// NumberofBroadcastRequestCodec binds the complete APER value type.
func NumberofBroadcastRequestCodec() s01.NumberofBroadcastRequestValueCodec {
	return WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Codec()
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

// RecommendedENBsForPagingCodec binds the complete source value type.
func RecommendedENBsForPagingCodec() RecommendedENBsForPagingValueCodec {
	return RecommendedENBsForPagingValueCodec{path: "RecommendedENBsForPaging", decode: func(data []byte, options aper.DecodeState) (RecommendedENBsForPaging, error) {
		var value RecommendedENBsForPaging
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return RecommendedENBsForPaging{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value RecommendedENBsForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v RecommendedENBsForPaging, options aper.DecodeState) (RecommendedENBsForPaging, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APRecommendedENBsForPaging(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v RecommendedENBsForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APRecommendedENBsForPaging(&v, &s)
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

// RepetitionPeriodCodec binds the complete APER value type.
func RepetitionPeriodCodec() s01.RepetitionPeriodValueCodec {
	return WriteReplaceWarningRequestIEs().RepetitionPeriod().Codec()
}

// TAIItemCodec binds the complete APER value type.
func TAIItemCodec() TAIItemValueCodec { return TAIItemIEs().TAIItem().Codec() }

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

// WarningAreaCoordinatesCodec binds the complete APER value type.
func WarningAreaCoordinatesCodec() s02.WarningAreaCoordinatesValueCodec {
	return WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Codec()
}

// WarningMessageContentsCodec binds the complete APER value type.
func WarningMessageContentsCodec() s02.WarningMessageContentsValueCodec {
	return WriteReplaceWarningRequestIEs().WarningMessageContents().Codec()
}

// WarningSecurityInfoCodec binds the complete APER value type.
func WarningSecurityInfoCodec() s02.WarningSecurityInfoValueCodec {
	return WriteReplaceWarningRequestIEs().WarningSecurityInfo().Codec()
}

// WarningTypeCodec binds the complete APER value type.
func WarningTypeCodec() s02.WarningTypeValueCodec {
	return WriteReplaceWarningRequestIEs().WarningType().Codec()
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
func BridgeKillRequestAPERValueFieldContext(v *KillRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestAPERValueFieldReceived(v *KillRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillRequestAPERValueFieldReplay(v *KillRequestAPERValue) *aper.Snapshot { return &v.replay }
func BridgeKillRequestAPERValueFieldWithoutReplay(v *KillRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillRequestFieldExtCount(v *KillRequest) *int64                { return &v.extCount }
func BridgeKillRequestFieldExtData(v *KillRequest) *[][]byte              { return &v.extData }
func BridgeKillRequestFieldExtOrigin(v *KillRequest) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeKillRequestFieldExtPresent(v *KillRequest) *[]bool             { return &v.extPresent }
func BridgeKillRequestFieldExtWire(v *KillRequest) *[]aper.WireSpan       { return &v.extWire }
func BridgeKillRequestFieldPerExtPadding(v *KillRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeKillRequestFieldPerPadding(v *KillRequest) *aper.FinalPadding { return &v.perPadding }
func BridgeKillRequestFieldProtocolIEsIndef(v *KillRequest) *bool        { return &v.protocolIEsIndef }
func BridgeKillRequestFieldReceived(v *KillRequest) *bool                { return &v.received }
func BridgeKillRequestFieldReceivedAbsolute(v *KillRequest) *bool        { return &v.receivedAbsolute }
func BridgeKillRequestFieldReceivedBytes(v *KillRequest) *aper.WireSpan  { return &v.receivedBytes }
func BridgeKillRequestFieldReceivedLocation(v *KillRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeKillRequestFieldReplay(v *KillRequest) *aper.Snapshot { return &v.replay }
func BridgeKillRequestFieldStream(v *KillRequest) *aper.WireSpan { return &v.stream }
func BridgeKillRequestFieldWithoutReplay(v *KillRequest) *bool   { return &v.withoutReplay }
func BridgeKillRequestMethodMarshalAPERBudget(v *KillRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeKillRequestMethodMarshalAPERBudgetValue(v *KillRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeKillRequestMethodMarshalAPERChanged(v *KillRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeKillRequestMethodMarshalAPERChangedValue(v *KillRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeKillRequestMethodMarshalAPERLegacy(v *KillRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeKillRequestMethodMarshalAPERNewValue(v *KillRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeKillRequestMethodMarshalAPERPlanned(v *KillRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeKillRequestMethodMarshalAPERTo(v *KillRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillRequestMethodUnmarshalAPERFrom(v *KillRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillRequestMethodUnmarshalAPERLegacy(v *KillRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeKillRequestMethodUnmarshalAPERWithOptions(v *KillRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeKillRequestValueCodecFieldCapture(v *KillRequestValueCodec) *func(KillRequest, aper.DecodeState) (KillRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeKillRequestValueCodecFieldCompare(v *KillRequestValueCodec) *func(KillRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillRequestValueCodecFieldContext(v *KillRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillRequestValueCodecFieldDecode(v *KillRequestValueCodec) *func([]byte, aper.DecodeState) (KillRequest, error) {
	return &v.decode
}
func BridgeKillRequestValueCodecFieldEncode(v *KillRequestValueCodec) *func(KillRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillRequestValueCodecFieldPath(v *KillRequestValueCodec) *aper.Path { return &v.path }
func BridgeKillRequestValueCodecMethodEncodeBudgetValue(v KillRequestValueCodec, a0 KillRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillRequestValueCodecMethodEncodeChanged(v KillRequestValueCodec, a0 KillRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeKillResponseAPERValueFieldContext(v *KillResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseAPERValueFieldReceived(v *KillResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeKillResponseAPERValueFieldReplay(v *KillResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeKillResponseAPERValueFieldWithoutReplay(v *KillResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeKillResponseFieldExtCount(v *KillResponse) *int64                { return &v.extCount }
func BridgeKillResponseFieldExtData(v *KillResponse) *[][]byte              { return &v.extData }
func BridgeKillResponseFieldExtOrigin(v *KillResponse) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeKillResponseFieldExtPresent(v *KillResponse) *[]bool             { return &v.extPresent }
func BridgeKillResponseFieldExtWire(v *KillResponse) *[]aper.WireSpan       { return &v.extWire }
func BridgeKillResponseFieldPerExtPadding(v *KillResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeKillResponseFieldPerPadding(v *KillResponse) *aper.FinalPadding { return &v.perPadding }
func BridgeKillResponseFieldProtocolIEsIndef(v *KillResponse) *bool        { return &v.protocolIEsIndef }
func BridgeKillResponseFieldReceived(v *KillResponse) *bool                { return &v.received }
func BridgeKillResponseFieldReceivedAbsolute(v *KillResponse) *bool        { return &v.receivedAbsolute }
func BridgeKillResponseFieldReceivedBytes(v *KillResponse) *aper.WireSpan  { return &v.receivedBytes }
func BridgeKillResponseFieldReceivedLocation(v *KillResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeKillResponseFieldReplay(v *KillResponse) *aper.Snapshot { return &v.replay }
func BridgeKillResponseFieldStream(v *KillResponse) *aper.WireSpan { return &v.stream }
func BridgeKillResponseFieldWithoutReplay(v *KillResponse) *bool   { return &v.withoutReplay }
func BridgeKillResponseMethodMarshalAPERBudget(v *KillResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeKillResponseMethodMarshalAPERBudgetValue(v *KillResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeKillResponseMethodMarshalAPERChanged(v *KillResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeKillResponseMethodMarshalAPERChangedValue(v *KillResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeKillResponseMethodMarshalAPERLegacy(v *KillResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeKillResponseMethodMarshalAPERNewValue(v *KillResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeKillResponseMethodMarshalAPERPlanned(v *KillResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeKillResponseMethodMarshalAPERTo(v *KillResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeKillResponseMethodUnmarshalAPERFrom(v *KillResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeKillResponseMethodUnmarshalAPERLegacy(v *KillResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeKillResponseMethodUnmarshalAPERWithOptions(v *KillResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeKillResponseValueCodecFieldCapture(v *KillResponseValueCodec) *func(KillResponse, aper.DecodeState) (KillResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseValueCodecFieldCompare(v *KillResponseValueCodec) *func(KillResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseValueCodecFieldContext(v *KillResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseValueCodecFieldDecode(v *KillResponseValueCodec) *func([]byte, aper.DecodeState) (KillResponse, error) {
	return &v.decode
}
func BridgeKillResponseValueCodecFieldEncode(v *KillResponseValueCodec) *func(KillResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseValueCodecFieldPath(v *KillResponseValueCodec) *aper.Path { return &v.path }
func BridgeKillResponseValueCodecMethodEncodeBudgetValue(v KillResponseValueCodec, a0 KillResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeKillResponseValueCodecMethodEncodeChanged(v KillResponseValueCodec, a0 KillResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLocationReportAPERValueFieldContext(v *LocationReportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportAPERValueFieldReceived(v *LocationReportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeLocationReportAPERValueFieldReplay(v *LocationReportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeLocationReportAPERValueFieldWithoutReplay(v *LocationReportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLocationReportFieldExtCount(v *LocationReport) *int64                { return &v.extCount }
func BridgeLocationReportFieldExtData(v *LocationReport) *[][]byte              { return &v.extData }
func BridgeLocationReportFieldExtOrigin(v *LocationReport) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeLocationReportFieldExtPresent(v *LocationReport) *[]bool             { return &v.extPresent }
func BridgeLocationReportFieldExtWire(v *LocationReport) *[]aper.WireSpan       { return &v.extWire }
func BridgeLocationReportFieldPerExtPadding(v *LocationReport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeLocationReportFieldPerPadding(v *LocationReport) *aper.FinalPadding { return &v.perPadding }
func BridgeLocationReportFieldProtocolIEsIndef(v *LocationReport) *bool        { return &v.protocolIEsIndef }
func BridgeLocationReportFieldReceived(v *LocationReport) *bool                { return &v.received }
func BridgeLocationReportFieldReceivedAbsolute(v *LocationReport) *bool        { return &v.receivedAbsolute }
func BridgeLocationReportFieldReceivedBytes(v *LocationReport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeLocationReportFieldReceivedLocation(v *LocationReport) *aper.Location {
	return &v.receivedLocation
}
func BridgeLocationReportFieldReplay(v *LocationReport) *aper.Snapshot { return &v.replay }
func BridgeLocationReportFieldStream(v *LocationReport) *aper.WireSpan { return &v.stream }
func BridgeLocationReportFieldWithoutReplay(v *LocationReport) *bool   { return &v.withoutReplay }
func BridgeLocationReportMethodMarshalAPERBudget(v *LocationReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLocationReportMethodMarshalAPERBudgetValue(v *LocationReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeLocationReportMethodMarshalAPERChanged(v *LocationReport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLocationReportMethodMarshalAPERChangedValue(v *LocationReport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLocationReportMethodMarshalAPERLegacy(v *LocationReport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeLocationReportMethodMarshalAPERNewValue(v *LocationReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeLocationReportMethodMarshalAPERPlanned(v *LocationReport, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeLocationReportMethodMarshalAPERTo(v *LocationReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLocationReportMethodUnmarshalAPERFrom(v *LocationReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLocationReportMethodUnmarshalAPERLegacy(v *LocationReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLocationReportMethodUnmarshalAPERWithOptions(v *LocationReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLocationReportValueCodecFieldCapture(v *LocationReportValueCodec) *func(LocationReport, aper.DecodeState) (LocationReport, aper.Snapshot) {
	return &v.capture
}
func BridgeLocationReportValueCodecFieldCompare(v *LocationReportValueCodec) *func(LocationReport, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLocationReportValueCodecFieldContext(v *LocationReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLocationReportValueCodecFieldDecode(v *LocationReportValueCodec) *func([]byte, aper.DecodeState) (LocationReport, error) {
	return &v.decode
}
func BridgeLocationReportValueCodecFieldEncode(v *LocationReportValueCodec) *func(LocationReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLocationReportValueCodecFieldPath(v *LocationReportValueCodec) *aper.Path { return &v.path }
func BridgeLocationReportValueCodecMethodEncodeBudgetValue(v LocationReportValueCodec, a0 LocationReport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeLocationReportValueCodecMethodEncodeChanged(v LocationReportValueCodec, a0 LocationReport, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeRecommendedENBsForPagingFieldExtCount(v *RecommendedENBsForPaging) *int64 {
	return &v.extCount
}
func BridgeRecommendedENBsForPagingFieldExtData(v *RecommendedENBsForPaging) *[][]byte {
	return &v.extData
}
func BridgeRecommendedENBsForPagingFieldExtOrigin(v *RecommendedENBsForPaging) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRecommendedENBsForPagingFieldExtPresent(v *RecommendedENBsForPaging) *[]bool {
	return &v.extPresent
}
func BridgeRecommendedENBsForPagingFieldExtWire(v *RecommendedENBsForPaging) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRecommendedENBsForPagingFieldIEExtensionsIndef(v *RecommendedENBsForPaging) *bool {
	return &v.iEExtensionsIndef
}
func BridgeRecommendedENBsForPagingFieldPerExtPadding(v *RecommendedENBsForPaging) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRecommendedENBsForPagingFieldPerPadding(v *RecommendedENBsForPaging) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRecommendedENBsForPagingFieldReceived(v *RecommendedENBsForPaging) *bool {
	return &v.received
}
func BridgeRecommendedENBsForPagingFieldReceivedAbsolute(v *RecommendedENBsForPaging) *bool {
	return &v.receivedAbsolute
}
func BridgeRecommendedENBsForPagingFieldReceivedBytes(v *RecommendedENBsForPaging) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRecommendedENBsForPagingFieldReceivedLocation(v *RecommendedENBsForPaging) *aper.Location {
	return &v.receivedLocation
}
func BridgeRecommendedENBsForPagingFieldRecommendedENBListIndef(v *RecommendedENBsForPaging) *bool {
	return &v.recommendedENBListIndef
}
func BridgeRecommendedENBsForPagingFieldReplay(v *RecommendedENBsForPaging) *aper.Snapshot {
	return &v.replay
}
func BridgeRecommendedENBsForPagingFieldStream(v *RecommendedENBsForPaging) *aper.WireSpan {
	return &v.stream
}
func BridgeRecommendedENBsForPagingFieldWithoutReplay(v *RecommendedENBsForPaging) *bool {
	return &v.withoutReplay
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERBudget(v *RecommendedENBsForPaging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERBudgetValue(v *RecommendedENBsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERChanged(v *RecommendedENBsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERChangedValue(v *RecommendedENBsForPaging, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERLegacy(v *RecommendedENBsForPaging) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERNewValue(v *RecommendedENBsForPaging, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERPlanned(v *RecommendedENBsForPaging, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeRecommendedENBsForPagingMethodMarshalAPERTo(v *RecommendedENBsForPaging, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRecommendedENBsForPagingMethodUnmarshalAPERFrom(v *RecommendedENBsForPaging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRecommendedENBsForPagingMethodUnmarshalAPERLegacy(v *RecommendedENBsForPaging, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRecommendedENBsForPagingMethodUnmarshalAPERWithOptions(v *RecommendedENBsForPaging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRecommendedENBsForPagingValueCodecFieldCapture(v *RecommendedENBsForPagingValueCodec) *func(RecommendedENBsForPaging, aper.DecodeState) (RecommendedENBsForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeRecommendedENBsForPagingValueCodecFieldCompare(v *RecommendedENBsForPagingValueCodec) *func(RecommendedENBsForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRecommendedENBsForPagingValueCodecFieldContext(v *RecommendedENBsForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRecommendedENBsForPagingValueCodecFieldDecode(v *RecommendedENBsForPagingValueCodec) *func([]byte, aper.DecodeState) (RecommendedENBsForPaging, error) {
	return &v.decode
}
func BridgeRecommendedENBsForPagingValueCodecFieldEncode(v *RecommendedENBsForPagingValueCodec) *func(RecommendedENBsForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRecommendedENBsForPagingValueCodecFieldPath(v *RecommendedENBsForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeRecommendedENBsForPagingValueCodecMethodEncodeBudgetValue(v RecommendedENBsForPagingValueCodec, a0 RecommendedENBsForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeRecommendedENBsForPagingValueCodecMethodEncodeChanged(v RecommendedENBsForPagingValueCodec, a0 RecommendedENBsForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeWriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBindingFieldCodec(v *WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) *s00.ConcurrentWarningMessageIndicatorValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBindingFieldGet(v *WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.ConcurrentWarningMessageIndicator, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBindingFieldInfo(v *WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBindingFieldInject(v *WriteReplaceWarningRequestConcurrentWarningMessageIndicatorIEBinding) *func(s00.ConcurrentWarningMessageIndicator) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestDataCodingSchemeIEBindingFieldCodec(v *WriteReplaceWarningRequestDataCodingSchemeIEBinding) *s00.DataCodingSchemeValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestDataCodingSchemeIEBindingFieldGet(v *WriteReplaceWarningRequestDataCodingSchemeIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.DataCodingScheme, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestDataCodingSchemeIEBindingFieldInfo(v *WriteReplaceWarningRequestDataCodingSchemeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestDataCodingSchemeIEBindingFieldInject(v *WriteReplaceWarningRequestDataCodingSchemeIEBinding) *func(s00.DataCodingScheme) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestExtendedRepetitionPeriodIEBindingFieldCodec(v *WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) *s00.ExtendedRepetitionPeriodValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestExtendedRepetitionPeriodIEBindingFieldGet(v *WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.ExtendedRepetitionPeriod, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestExtendedRepetitionPeriodIEBindingFieldInfo(v *WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestExtendedRepetitionPeriodIEBindingFieldInject(v *WriteReplaceWarningRequestExtendedRepetitionPeriodIEBinding) *func(s00.ExtendedRepetitionPeriod) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestIEContainerAPERValueFieldContext(v *WriteReplaceWarningRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEContainerAPERValueFieldReceived(v *WriteReplaceWarningRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEContainerAPERValueFieldReplay(v *WriteReplaceWarningRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEContainerAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCapture(v *WriteReplaceWarningRequestIEContainerValueCodec) *func(WriteReplaceWarningRequestIEContainer, aper.DecodeState) (WriteReplaceWarningRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCompare(v *WriteReplaceWarningRequestIEContainerValueCodec) *func(WriteReplaceWarningRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldContext(v *WriteReplaceWarningRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(v *WriteReplaceWarningRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEContainer, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(v *WriteReplaceWarningRequestIEContainerValueCodec) *func(WriteReplaceWarningRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldPath(v *WriteReplaceWarningRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestIEContainerValueCodec, a0 WriteReplaceWarningRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestIEContainerValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestIEContainerValueCodec, a0 WriteReplaceWarningRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningRequestIEFieldAPERValueFieldContext(v *WriteReplaceWarningRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEFieldAPERValueFieldReceived(v *WriteReplaceWarningRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEFieldAPERValueFieldReplay(v *WriteReplaceWarningRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEFieldAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEFieldFieldReceived(v *WriteReplaceWarningRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEFieldFieldReplay(v *WriteReplaceWarningRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEFieldFieldStream(v *WriteReplaceWarningRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeWriteReplaceWarningRequestIEFieldFieldWithoutReplay(v *WriteReplaceWarningRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(v *WriteReplaceWarningRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(v *WriteReplaceWarningRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCapture(v *WriteReplaceWarningRequestIEFieldValueCodec) *func(WriteReplaceWarningRequestIEField, aper.DecodeState) (WriteReplaceWarningRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCompare(v *WriteReplaceWarningRequestIEFieldValueCodec) *func(WriteReplaceWarningRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldContext(v *WriteReplaceWarningRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldDecode(v *WriteReplaceWarningRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEField, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldEncode(v *WriteReplaceWarningRequestIEFieldValueCodec) *func(WriteReplaceWarningRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldPath(v *WriteReplaceWarningRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestIEFieldValueCodec, a0 WriteReplaceWarningRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestIEFieldValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestIEFieldValueCodec, a0 WriteReplaceWarningRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoConcurrentWarningMessageIndicator(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoConcurrentWarningMessageIndicator()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoDataCodingScheme(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoDataCodingScheme()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoExtendedRepetitionPeriod(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoExtendedRepetitionPeriod()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoMessageIdentifier(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoMessageIdentifier()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoNumberofBroadcastRequest(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoNumberofBroadcastRequest()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoRepetitionPeriod(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoRepetitionPeriod()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoSerialNumber(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoSerialNumber()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoWarningAreaCoordinates(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoWarningAreaCoordinates()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoWarningAreaList(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoWarningAreaList()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoWarningMessageContents(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoWarningMessageContents()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoWarningSecurityInfo(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoWarningSecurityInfo()
}
func BridgeWriteReplaceWarningRequestIETableMethodInfoWarningType(v WriteReplaceWarningRequestIETable) s00.FieldInfo {
	return v.infoWarningType()
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListAPERValueFieldContext(v *WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueERABIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldContext(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldPath(v *WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningRequestIEValueFieldId(v *WriteReplaceWarningRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWriteReplaceWarningRequestIEValueFieldIsOpaque(v *WriteReplaceWarningRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeWriteReplaceWarningRequestIEValueFieldOpaque(v *WriteReplaceWarningRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWriteReplaceWarningRequestIEValueFieldReceived(v *WriteReplaceWarningRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEValueFieldReplay(v *WriteReplaceWarningRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowConcurrentWarningMessageIndicator(v *WriteReplaceWarningRequestIEValue) **s00.ConcurrentWarningMessageIndicator {
	return &v.rowConcurrentWarningMessageIndicator
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowDataCodingScheme(v *WriteReplaceWarningRequestIEValue) **s00.DataCodingScheme {
	return &v.rowDataCodingScheme
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowExtendedRepetitionPeriod(v *WriteReplaceWarningRequestIEValue) **s00.ExtendedRepetitionPeriod {
	return &v.rowExtendedRepetitionPeriod
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowMessageIdentifier(v *WriteReplaceWarningRequestIEValue) **s00.MessageIdentifier {
	return &v.rowMessageIdentifier
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowNumberofBroadcastRequest(v *WriteReplaceWarningRequestIEValue) **s00.NumberofBroadcastRequest {
	return &v.rowNumberofBroadcastRequest
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowRepetitionPeriod(v *WriteReplaceWarningRequestIEValue) **s00.RepetitionPeriod {
	return &v.rowRepetitionPeriod
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowSerialNumber(v *WriteReplaceWarningRequestIEValue) **s00.SerialNumber {
	return &v.rowSerialNumber
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaCoordinates(v *WriteReplaceWarningRequestIEValue) **s00.WarningAreaCoordinates {
	return &v.rowWarningAreaCoordinates
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningAreaList(v *WriteReplaceWarningRequestIEValue) **s32.WarningAreaList {
	return &v.rowWarningAreaList
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningMessageContents(v *WriteReplaceWarningRequestIEValue) **s00.WarningMessageContents {
	return &v.rowWarningMessageContents
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningSecurityInfo(v *WriteReplaceWarningRequestIEValue) **s00.WarningSecurityInfo {
	return &v.rowWarningSecurityInfo
}
func BridgeWriteReplaceWarningRequestIEValueFieldRowWarningType(v *WriteReplaceWarningRequestIEValue) **s00.WarningType {
	return &v.rowWarningType
}
func BridgeWriteReplaceWarningRequestIEValueMethodCaptureSemantics(v WriteReplaceWarningRequestIEValue, a0 aper.SemanticCapture) WriteReplaceWarningRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeWriteReplaceWarningRequestIEValueMethodCompareSemantics(v WriteReplaceWarningRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWriteReplaceWarningRequestIEValueMethodDecode(v WriteReplaceWarningRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WriteReplaceWarningRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeWriteReplaceWarningRequestIEValueMethodEncode(v WriteReplaceWarningRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeWriteReplaceWarningRequestIEValueMethodEncodeFresh(v WriteReplaceWarningRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWriteReplaceWarningRequestIEValueMethodMatchesID(v WriteReplaceWarningRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeWriteReplaceWarningRequestIEValueMethodReason(v WriteReplaceWarningRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWriteReplaceWarningRequestIEValueMethodRule(v WriteReplaceWarningRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *func(WriteReplaceWarningRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec, a0 WriteReplaceWarningRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningRequestMessageIdentifierIEBindingFieldCodec(v *WriteReplaceWarningRequestMessageIdentifierIEBinding) *s01.MessageIdentifierValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestMessageIdentifierIEBindingFieldGet(v *WriteReplaceWarningRequestMessageIdentifierIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.MessageIdentifier, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestMessageIdentifierIEBindingFieldInfo(v *WriteReplaceWarningRequestMessageIdentifierIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestMessageIdentifierIEBindingFieldInject(v *WriteReplaceWarningRequestMessageIdentifierIEBinding) *func(s00.MessageIdentifier) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestNumberofBroadcastRequestIEBindingFieldCodec(v *WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) *s01.NumberofBroadcastRequestValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestNumberofBroadcastRequestIEBindingFieldGet(v *WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.NumberofBroadcastRequest, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestNumberofBroadcastRequestIEBindingFieldInfo(v *WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestNumberofBroadcastRequestIEBindingFieldInject(v *WriteReplaceWarningRequestNumberofBroadcastRequestIEBinding) *func(s00.NumberofBroadcastRequest) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestRepetitionPeriodIEBindingFieldCodec(v *WriteReplaceWarningRequestRepetitionPeriodIEBinding) *s01.RepetitionPeriodValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestRepetitionPeriodIEBindingFieldGet(v *WriteReplaceWarningRequestRepetitionPeriodIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.RepetitionPeriod, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestRepetitionPeriodIEBindingFieldInfo(v *WriteReplaceWarningRequestRepetitionPeriodIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestRepetitionPeriodIEBindingFieldInject(v *WriteReplaceWarningRequestRepetitionPeriodIEBinding) *func(s00.RepetitionPeriod) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestSerialNumberIEBindingFieldCodec(v *WriteReplaceWarningRequestSerialNumberIEBinding) *s01.SerialNumberValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestSerialNumberIEBindingFieldGet(v *WriteReplaceWarningRequestSerialNumberIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.SerialNumber, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestSerialNumberIEBindingFieldInfo(v *WriteReplaceWarningRequestSerialNumberIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestSerialNumberIEBindingFieldInject(v *WriteReplaceWarningRequestSerialNumberIEBinding) *func(s00.SerialNumber) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestWarningAreaCoordinatesIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) *s02.WarningAreaCoordinatesValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningAreaCoordinatesIEBindingFieldGet(v *WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.WarningAreaCoordinates, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningAreaCoordinatesIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningAreaCoordinatesIEBindingFieldInject(v *WriteReplaceWarningRequestWarningAreaCoordinatesIEBinding) *func(s00.WarningAreaCoordinates) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *s32.WarningAreaListValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldGet(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s32.WarningAreaList, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningAreaListIEBindingFieldInject(v *WriteReplaceWarningRequestWarningAreaListIEBinding) *func(s32.WarningAreaList) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestWarningMessageContentsIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningMessageContentsIEBinding) *s02.WarningMessageContentsValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningMessageContentsIEBindingFieldGet(v *WriteReplaceWarningRequestWarningMessageContentsIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.WarningMessageContents, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningMessageContentsIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningMessageContentsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningMessageContentsIEBindingFieldInject(v *WriteReplaceWarningRequestWarningMessageContentsIEBinding) *func(s00.WarningMessageContents) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestWarningSecurityInfoIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningSecurityInfoIEBinding) *s02.WarningSecurityInfoValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningSecurityInfoIEBindingFieldGet(v *WriteReplaceWarningRequestWarningSecurityInfoIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.WarningSecurityInfo, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningSecurityInfoIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningSecurityInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningSecurityInfoIEBindingFieldInject(v *WriteReplaceWarningRequestWarningSecurityInfoIEBinding) *func(s00.WarningSecurityInfo) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
func BridgeWriteReplaceWarningRequestWarningTypeIEBindingFieldCodec(v *WriteReplaceWarningRequestWarningTypeIEBinding) *s02.WarningTypeValueCodec {
	return &v.codec
}
func BridgeWriteReplaceWarningRequestWarningTypeIEBindingFieldGet(v *WriteReplaceWarningRequestWarningTypeIEBinding) *func(*WriteReplaceWarningRequestIEValue) (*s00.WarningType, bool) {
	return &v.get
}
func BridgeWriteReplaceWarningRequestWarningTypeIEBindingFieldInfo(v *WriteReplaceWarningRequestWarningTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWriteReplaceWarningRequestWarningTypeIEBindingFieldInject(v *WriteReplaceWarningRequestWarningTypeIEBinding) *func(s00.WarningType) WriteReplaceWarningRequestIEValue {
	return &v.inject
}
